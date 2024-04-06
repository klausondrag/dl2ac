import enum
import sys

import docker
import typer
from docker.models.containers import Container as DockerContainer
from loguru import logger
from typing_extensions import Annotated

from dl2ac import models

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
    docker_containers = client.containers.list()
    logger.info(f'Found {len(docker_containers)} containers')

    raw_containers = load(docker_containers)
    logger.debug(f'{raw_containers=}')

    parsed_containers = parse(docker_containers)
    logger.debug(f'{parsed_containers=}')

    logger.info('Restarting Authelia containers')
    for container in parsed_containers:
        if container.is_authelia:
            logger.info(f'Restarting {container.name}...')
            container.container.restart()


def load(
    docker_containers: list[DockerContainer],
) -> list[models.RawContainer]:
    # TODO: handle DockerException
    return [
        models.RawContainer(container, container.name, container.labels)
        for container in docker_containers
    ]


def parse(
    raw_containers: list[models.RawContainer],
) -> list[models.ParsedContainer]:
    return [
        parsed_container
        for container in raw_containers
        if (parsed_container := models.ParsedContainer.from_raw(container)) is not None
    ]


if __name__ == '__main__':
    app()
