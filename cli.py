import typer

from python_template import example

app = typer.Typer()
app.add_typer(example.app, name='example')


if __name__ == '__main__':
    app()
