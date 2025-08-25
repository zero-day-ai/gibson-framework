"""Report generation commands."""

import typer

app = typer.Typer(help="Report generation")


@app.command()
def generate():
    """Generate report."""
    print("Report generation not yet implemented")
