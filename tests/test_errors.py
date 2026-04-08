"""Tests for specter error hierarchy (Story 1.3, AC2, AC3)."""
import pytest

from specter.errors import (
    AgentError,
    ConfigError,
    SkfnContainerError,
    SkfnParseError,
    SprecterError,
    SprecterValidationError,
)


class TestSprecterErrorBase:
    def test_is_exception_subclass(self):
        assert issubclass(SprecterError, Exception)

    def test_base_exit_code_is_3(self):
        err = SprecterError("base error")
        assert err.exit_code == 3

    def test_preserves_message(self):
        err = SprecterError("something went wrong")
        assert str(err) == "something went wrong"

    def test_is_catchable_as_exception(self):
        with pytest.raises(Exception):
            raise SprecterError("boom")


class TestSkfnContainerError:
    def test_exit_code_is_3(self):
        assert SkfnContainerError("container failed").exit_code == 3

    def test_is_specter_error(self):
        assert issubclass(SkfnContainerError, SprecterError)

    def test_message_preserved(self):
        err = SkfnContainerError("container crashed")
        assert "container crashed" in str(err)


class TestSkfnParseError:
    def test_exit_code_is_3(self):
        assert SkfnParseError("parse failed").exit_code == 3

    def test_is_specter_error(self):
        assert issubclass(SkfnParseError, SprecterError)


class TestAgentError:
    def test_exit_code_is_3(self):
        assert AgentError("agent failed").exit_code == 3

    def test_is_specter_error(self):
        assert issubclass(AgentError, SprecterError)


class TestSprecterValidationError:
    def test_exit_code_is_3(self):
        assert SprecterValidationError("validation failed").exit_code == 3

    def test_is_specter_error(self):
        assert issubclass(SprecterValidationError, SprecterError)

    def test_name_does_not_conflict_with_pydantic(self):
        """SprecterValidationError must not shadow pydantic.ValidationError."""
        from pydantic import ValidationError as PydanticValidationError

        assert SprecterValidationError is not PydanticValidationError


class TestConfigError:
    def test_exit_code_is_3(self):
        assert ConfigError("config missing").exit_code == 3

    def test_is_specter_error(self):
        assert issubclass(ConfigError, SprecterError)


class TestAllSubclassesHaveExitCode3:
    """AC2: All SprecterError subclasses have exit_code == 3."""

    @pytest.mark.parametrize(
        "error_class",
        [
            SkfnContainerError,
            SkfnParseError,
            AgentError,
            SprecterValidationError,
            ConfigError,
        ],
    )
    def test_exit_code_is_3(self, error_class):
        err = error_class("test")
        assert err.exit_code == 3

    @pytest.mark.parametrize(
        "error_class",
        [
            SkfnContainerError,
            SkfnParseError,
            AgentError,
            SprecterValidationError,
            ConfigError,
        ],
    )
    def test_catchable_as_specter_error(self, error_class):
        with pytest.raises(SprecterError):
            raise error_class("test")


class TestErrorsModuleHasNoSprecterImports:
    """AC3: errors.py must not import from specter."""

    def test_no_specter_imports_in_errors_module(self):
        import ast
        import pathlib

        errors_path = pathlib.Path(__file__).parent.parent / "src/specter/errors.py"
        tree = ast.parse(errors_path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("specter"), (
                        f"errors.py must not import from specter, found: {alias.name}"
                    )
            if isinstance(node, ast.ImportFrom):
                if node.module:
                    assert not node.module.startswith("specter"), (
                        f"errors.py must not import from specter, found: {node.module}"
                    )


class TestNoPipelineModulesDefineExceptions:
    """AC3: No Exception subclasses may be defined outside errors.py.

    Scans all pipeline source modules for inline Exception class definitions.
    Catches violations early — before pipeline modules are committed.
    """

    def test_no_exception_subclasses_in_pipeline_modules(self):
        import ast
        import pathlib

        src_root = pathlib.Path(__file__).parent.parent / "src" / "specter"
        errors_path = src_root / "errors.py"

        # Collect all .py files under src/specter except errors.py itself
        candidate_files = [
            p for p in src_root.rglob("*.py") if p.resolve() != errors_path.resolve()
        ]

        violations: list[str] = []
        for py_file in candidate_files:
            tree = ast.parse(py_file.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    for base in node.bases:
                        # Catches: class Foo(Exception), class Foo(ValueError), etc.
                        base_name = (
                            base.id
                            if isinstance(base, ast.Name)
                            else base.attr
                            if isinstance(base, ast.Attribute)
                            else None
                        )
                        if base_name and (
                            base_name == "Exception"
                            or base_name.endswith("Error")
                            or base_name.endswith("Exception")
                        ):
                            rel = py_file.relative_to(src_root.parent.parent)
                            violations.append(
                                f"{rel}:{node.lineno} — class {node.name}({base_name})"
                            )

        assert not violations, (
            "AC3 violation — Exception subclasses defined outside errors.py:\n"
            + "\n".join(violations)
        )
