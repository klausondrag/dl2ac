import typer

from dl2ac import example, entry

app = typer.Typer()
app.add_typer(example.app, name='example')
app.add_typer(entry.app, name='dl2ac')


if __name__ == '__main__':
    app()
