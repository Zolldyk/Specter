"""Claude / OpenAI / Gemini agent call — pipeline stage 3.

Provider selection (first key found wins): ANTHROPIC_API_KEY → OPENAI_API_KEY → GEMINI_API_KEY.

Imports: specter.errors, specter.models, specter.config, stdlib, anthropic, openai, google-genai only.
Never imports from specter.cli, specter.pipeline.runner, specter.pipeline.parser,
specter.pipeline.validator, or specter.output.*.
"""
import json
import logging
import os

import anthropic
import openai
from google import genai
from google.genai import types as genai_types
from pydantic import ValidationError

from specter.config import MODEL_VERSION, OPENAI_MODEL_VERSION, GEMINI_MODEL_VERSION
from specter.errors import AgentError
from specter.models import AgentCalldata, SkfnContext

logger = logging.getLogger(__name__)

_SUBMIT_CALLDATA_TOOL = {
    "name": "submit_calldata",
    "description": (
        "Submit the proposed exploit calldata for EVM validation. "
        "Provide exact hex-encoded calldata that reaches the vulnerable CALL instruction."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "calldata": {
                "type": "string",
                "description": "0x-prefixed hex calldata to send to the target contract",
            },
            "target_address": {
                "type": "string",
                "description": "0x-prefixed target contract address (20 bytes)",
            },
            "value": {
                "type": "integer",
                "description": "ETH value in wei to send with the transaction (usually 0)",
            },
            "caller": {
                "type": "string",
                "description": "0x-prefixed caller/msg.sender address (20 bytes)",
            },
            "origin": {
                "type": "string",
                "description": "0x-prefixed tx.origin address (20 bytes)",
            },
        },
        "required": ["calldata", "target_address", "caller", "origin"],
    },
}


def _build_prompt(context: SkfnContext) -> str:
    """Build the vulnerability analysis prompt from a SkfnContext."""
    lines = [
        "You are analyzing an Ethereum smart contract for an exploitable vulnerability.",
        f"Contract address: {context.contract_address}",
    ]
    if context.vulnerability_type:
        lines.append(f"Vulnerability type: {context.vulnerability_type}")
    if context.confidence:
        lines.append(f"Confidence: {context.confidence}")
    if context.call_pc:
        lines.append(f"Vulnerable CALL program counter: {context.call_pc}")
    if context.key_selector:
        lines.append(f"Key function selector: {context.key_selector}")
    lines.append("")
    lines.append("SKANF analysis output (raw):")
    lines.append(context.raw_output[:4000])  # truncate to avoid token overflow
    lines.append("")
    lines.append(
        "Using the vulnerability context above, construct calldata that will reach and trigger "
        "the vulnerable CALL instruction. Use the submit_calldata tool to return your answer."
    )
    return "\n".join(lines)


def _call_anthropic(context: SkfnContext, *, timeout: float | None = None) -> AgentCalldata:
    """Call the Claude API to generate exploit calldata."""
    prompt = _build_prompt(context)
    logger.debug("Anthropic agent: sending prompt (%d chars)", len(prompt))

    client = anthropic.Anthropic(
        api_key=os.environ.get("ANTHROPIC_API_KEY"),
        timeout=timeout,
    )

    try:
        response = client.messages.create(
            model=MODEL_VERSION,
            max_tokens=1024,
            tools=[_SUBMIT_CALLDATA_TOOL],
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.APIStatusError as exc:
        raise AgentError(f"Claude API returned HTTP {exc.status_code}: {exc}") from exc
    except anthropic.APIConnectionError as exc:
        raise AgentError(f"Claude API connection error: {exc}") from exc
    except anthropic.APIError as exc:
        raise AgentError(f"Claude API error: {exc}") from exc

    logger.debug("Anthropic agent: response stop_reason=%r", response.stop_reason)

    if response.model != MODEL_VERSION:
        raise AgentError(
            f"Claude API returned model {response.model!r} but expected {MODEL_VERSION!r} — "
            f"model may have changed or been deprecated"
        )

    tool_use_block = next(
        (b for b in response.content if b.type == "tool_use" and b.name == "submit_calldata"),
        None,
    )
    if tool_use_block is None:
        raise AgentError(
            "Claude API did not return a submit_calldata tool use block — "
            f"response content types: {[b.type for b in response.content]}"
        )

    logger.debug("Anthropic agent: tool input: %r", tool_use_block.input)

    try:
        agent_calldata = AgentCalldata(**tool_use_block.input)
    except (ValidationError, TypeError) as exc:
        raise AgentError(
            f"Claude API tool response failed validation — cannot construct AgentCalldata: {exc}"
        ) from exc

    logger.info(
        "Anthropic agent call complete — calldata=%r target=%r",
        agent_calldata.calldata[:18] + "...",
        agent_calldata.target_address,
    )
    return agent_calldata


def _call_openai(context: SkfnContext, *, timeout: float | None = None) -> AgentCalldata:
    """Call the OpenAI API to generate exploit calldata."""
    prompt = _build_prompt(context)
    logger.debug("OpenAI agent: sending prompt (%d chars)", len(prompt))

    openai_tool = {
        "type": "function",
        "function": {
            "name": _SUBMIT_CALLDATA_TOOL["name"],
            "description": _SUBMIT_CALLDATA_TOOL["description"],
            "parameters": _SUBMIT_CALLDATA_TOOL["input_schema"],
        },
    }

    client = openai.OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
        timeout=timeout,
    )

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL_VERSION,
            max_tokens=1024,
            tools=[openai_tool],
            tool_choice={"type": "function", "function": {"name": "submit_calldata"}},
            messages=[{"role": "user", "content": prompt}],
        )
    except openai.APIStatusError as exc:
        raise AgentError(f"OpenAI API returned HTTP {exc.status_code}: {exc}") from exc
    except openai.APIConnectionError as exc:
        raise AgentError(f"OpenAI API connection error: {exc}") from exc
    except openai.APIError as exc:
        raise AgentError(f"OpenAI API error: {exc}") from exc

    logger.debug("OpenAI agent: finish_reason=%r", response.choices[0].finish_reason)

    tool_call = next(
        (tc for tc in (response.choices[0].message.tool_calls or [])
         if tc.function.name == "submit_calldata"),
        None,
    )
    if tool_call is None:
        raise AgentError(
            "OpenAI API did not return a submit_calldata tool call — "
            f"finish_reason: {response.choices[0].finish_reason!r}"
        )

    try:
        tool_input = json.loads(tool_call.function.arguments)
    except json.JSONDecodeError as exc:
        raise AgentError(f"OpenAI tool call arguments not valid JSON: {exc}") from exc

    logger.debug("OpenAI agent: tool input: %r", tool_input)

    try:
        agent_calldata = AgentCalldata(**tool_input)
    except (ValidationError, TypeError) as exc:
        raise AgentError(
            f"OpenAI tool response failed validation — cannot construct AgentCalldata: {exc}"
        ) from exc

    logger.info(
        "OpenAI agent call complete — calldata=%r target=%r",
        agent_calldata.calldata[:18] + "...",
        agent_calldata.target_address,
    )
    return agent_calldata


def _call_gemini(context: SkfnContext, *, timeout: float | None = None) -> AgentCalldata:
    """Call the Gemini API to generate exploit calldata."""
    prompt = _build_prompt(context)
    logger.debug("Gemini agent: sending prompt (%d chars)", len(prompt))

    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

    fn_decl = genai_types.FunctionDeclaration(
        name=_SUBMIT_CALLDATA_TOOL["name"],
        description=_SUBMIT_CALLDATA_TOOL["description"],
        parameters=genai_types.Schema(
            type=genai_types.Type.OBJECT,
            properties={
                "calldata": genai_types.Schema(
                    type=genai_types.Type.STRING,
                    description="0x-prefixed hex calldata to send to the target contract",
                ),
                "target_address": genai_types.Schema(
                    type=genai_types.Type.STRING,
                    description="0x-prefixed target contract address (20 bytes)",
                ),
                "value": genai_types.Schema(
                    type=genai_types.Type.INTEGER,
                    description="ETH value in wei to send with the transaction (usually 0)",
                ),
                "caller": genai_types.Schema(
                    type=genai_types.Type.STRING,
                    description="0x-prefixed caller/msg.sender address (20 bytes)",
                ),
                "origin": genai_types.Schema(
                    type=genai_types.Type.STRING,
                    description="0x-prefixed tx.origin address (20 bytes)",
                ),
            },
            required=["calldata", "target_address", "caller", "origin"],
        ),
    )

    tool = genai_types.Tool(function_declarations=[fn_decl])

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL_VERSION,
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                tools=[tool],
                tool_config=genai_types.ToolConfig(
                    function_calling_config=genai_types.FunctionCallingConfig(
                        mode=genai_types.FunctionCallingConfigMode.ANY,
                        allowed_function_names=["submit_calldata"],
                    )
                ),
            ),
        )
    except Exception as exc:
        raise AgentError(f"Gemini API error: {exc}") from exc

    # Extract the function call from the response
    function_call = None
    for part in response.candidates[0].content.parts:
        if part.function_call and part.function_call.name == "submit_calldata":
            function_call = part.function_call
            break

    if function_call is None:
        raise AgentError(
            "Gemini API did not return a submit_calldata function call — "
            f"finish_reason: {response.candidates[0].finish_reason!r}"
        )

    tool_input = dict(function_call.args)
    logger.debug("Gemini agent: tool input: %r", tool_input)

    try:
        agent_calldata = AgentCalldata(**tool_input)
    except (ValidationError, TypeError) as exc:
        raise AgentError(
            f"Gemini tool response failed validation — cannot construct AgentCalldata: {exc}"
        ) from exc

    logger.info(
        "Gemini agent call complete — calldata=%r target=%r",
        agent_calldata.calldata[:18] + "...",
        agent_calldata.target_address,
    )
    return agent_calldata


def call_agent(
    context: SkfnContext,
    *,
    timeout: float | None = None,
) -> AgentCalldata:
    """Generate exploit calldata using the available AI provider.

    Priority: ANTHROPIC_API_KEY → OPENAI_API_KEY → GEMINI_API_KEY.

    Args:
        context: Parsed SKANF vulnerability context from parse_skanf().
        timeout: Wall-clock budget in seconds.

    Returns:
        AgentCalldata with calldata and transaction parameters.

    Raises:
        AgentError: API call failed, response missing tool use, or tool fields invalid.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        logger.info("Agent: using Anthropic provider")
        return _call_anthropic(context, timeout=timeout)
    elif os.environ.get("OPENAI_API_KEY"):
        logger.info("Agent: using OpenAI provider")
        return _call_openai(context, timeout=timeout)
    elif os.environ.get("GEMINI_API_KEY"):
        logger.info("Agent: using Gemini provider")
        return _call_gemini(context, timeout=timeout)
    else:
        raise AgentError(
            "No AI provider configured — set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY"
        )
