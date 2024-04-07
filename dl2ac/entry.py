import collections
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
    docker_containers: list[DockerContainer] = client.containers.list()
    logger.info(f'Found {len(docker_containers)} containers')

    raw_containers: list[models.RawContainer] = load_containers(docker_containers)
    logger.debug(f'{raw_containers=}')

    parsed_containers: list[models.ParsedContainer] = parse_containers(raw_containers)
    logger.debug(f'{parsed_containers=}')

    all_labels: list[models.RuleLabel] = load_rules(parsed_containers)
    logger.debug(f'{all_labels=}')

    parsed_rules: list[models.ParsedRule] = parse_rules(all_labels)
    logger.debug(f'{parsed_rules=}')

    restart_containers(parsed_containers)


def load_containers(
    docker_containers: list[DockerContainer],
) -> list[models.RawContainer]:
    # TODO: handle DockerException
    return [
        models.RawContainer(
            docker_container=docker_container,
            name=docker_container.name,
            labels=docker_container.labels,
        )
        for docker_container in docker_containers
    ]


def parse_containers(
    raw_containers: list[models.RawContainer],
) -> list[models.ParsedContainer]:
    return [
        parsed_container
        for raw_container in raw_containers
        if (parsed_container := models.ParsedContainer.from_raw(raw_container))
        is not None
    ]


def load_rules(
    parsed_containers: list[models.ParsedContainer],
) -> list[models.RuleLabel]:
    return [
        label
        for parsed_container in parsed_containers
        for label in parsed_container.labels
    ]


def parse_rules(
    label_list: list[models.RuleLabel],
) -> list[models.ParsedRule]:
    raw_rules: dict[str, models.RawRule] = collections.defaultdict(models.RawRule)
    for label in label_list:
        rule = raw_rules[label.rule_name]
        label.add_self_to(rule)

    parsed_rules = [
        parsed_rule
        for rule_name, rule in raw_rules.items()
        if (parsed_rule := models.ParsedRule.from_raw(rule, rule_name)) is not None
    ]
    return parsed_rules


def restart_containers(parsed_containers: list[models.ParsedContainer]):
    logger.debug('Restarting Authelia containers...')
    for container in parsed_containers:
        if container.is_authelia:
            logger.debug(f'Restarting {container.name}...')
            container.docker_container.restart()

    logger.info('Finished restarting Authelia containers.')


if __name__ == '__main__':
    app()
