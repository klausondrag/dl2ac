import dataclasses
import enum
import sys

import docker
import typer
from docker.models.containers import Container
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


@dataclasses.dataclass
class RawContainer:
    name: str
    labels: dict[str, str]


@app.command()
def entry(
    log_level: Annotated[LogLevel, typer.Option(case_sensitive=False)] = LogLevel.INFO,
) -> None:
    logger.remove()
    logger.add(sys.stderr, level=log_level.value)

    client = docker.from_env()
    containers = client.containers.list()
    logger.debug(f'Found {len(containers)} containers')

    if len(containers) > 0:
        logger.debug(type(containers[0]))

    raw_containers = load_containers(containers)
    logger.debug(raw_containers)


def load_containers(
    containers: list[Container],
) -> list[RawContainer]:
    return [RawContainer(container.name, container.labels) for container in containers]


if __name__ == '__main__':
    app()
