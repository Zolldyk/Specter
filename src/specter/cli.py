import typer

app = typer.Typer(rich_markup_mode=None)


@app.command()
def scan(target: str) -> None:
    """Scan a smart contract by address or bytecode."""
    pass


@app.command()
def check() -> None:
    """Verify all dependencies and environment variables are configured."""
    pass


@app.command()
def version() -> None:
    """Display the installed version and pinned dependency versions."""
    pass
