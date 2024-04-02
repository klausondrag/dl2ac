import enum
import sys

import docker
import typer
from loguru import logger
from typing_extensions import Annotated

app = typer.Typer()


class LogLevel(str, enum.Enum):
    TRACE = 'TRACE'
    DEBUG = 'DEBUG'
    INFO = 'INFO'
    SUCCESS = 'SUCCESS'
    WARNING = 'WARNING'
    ERROR = 'ERROR'
    CRITICAL = 'CRITICAL'


@app.command()
def entry(
    log_level: Annotated[LogLevel, typer.Option(case_sensitive=False)] = LogLevel.INFO,
) -> None:
    logger.remove()
    logger.add(sys.stderr, level=log_level.value)

    client = docker.from_env()
    containers = client.containers.list()
    logger.debug(f'Found {len(containers)} containers')


if __name__ == '__main__':
    app()
