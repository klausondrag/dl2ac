import abc
import dataclasses
import enum
import sys
from typing import Self

import docker
import typer
from docker.models.containers import Container as DockerContainer
from loguru import logger
from typing_extensions import Annotated

from dl2ac import config

app = typer.Typer()


class LogLevel(str, enum.Enum):
    TRACE = 'TRACE'
    DEBUG = 'DEBUG'
    INFO = 'INFO'
    SUCCESS = 'SUCCESS'
    WARNING = 'WARNING'
    ERROR = 'ERROR'
    CRITICAL = 'CRITICAL'


# Reference: https://www.authelia.com/configuration/security/access-control/#policies
class AutheliaPolicy(str, enum.Enum):
    DENY = 'deny'
    BYPASS = 'bypass'
    ONE_FACTOR = 'one_factor'
    TWO_FACTOR = 'two_factor'


allowed_authelia_policy_values = ', '.join(
    f'`{policy.value}`' for policy in AutheliaPolicy
)
logger.info(f'Allowed Authelia Policy Values: {allowed_authelia_policy_values}')


class LabelBase(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        pass


@dataclasses.dataclass
class IsAutheliaLabel(LabelBase):
    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.is-authelia': true
        # TODO: also support false to keep container inside logging
        if (
            label_key == config.AUTHELIA_VALUE
            and label_value.lower() == config.AUTHELIA_VALUE
        ):
            return cls()

        return None


@dataclasses.dataclass
class RuleLabel(LabelBase, abc.ABC):
    rule_name: str


@dataclasses.dataclass
class PolicyLabel(RuleLabel):
    policy: AutheliaPolicy

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.policy': 'one_factor'
        if match := config.POLICY_KEY_REGEX.match(label_key):
            rule_name = match.group(1)

            try:
                policy = AutheliaPolicy[label_value.upper()]
            except KeyError:
                # TODO: add container id, container name, and label_key
                logger.warning(
                    f'Invalid policy value found, cannot parse `{label_value}` as a policy.'
                    f' Must be one of [{allowed_authelia_policy_values}].'
                )
                return None

            return cls(rule_name=rule_name, policy=policy)

        return None


@dataclasses.dataclass
class PriorityLabel(RuleLabel):
    priority: int

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.priority': '20'
        if match := config.PRIORITY_KEY_REGEX.match(label_key):
            rule_name = match.group(1)

            try:
                priority = int(label_value)
            except ValueError:
                # TODO: add container id, container name, and label_key
                logger.warning(
                    f'Invalid priority value found, cannot parse `{label_value}` as int.'
                )
                return None

            return cls(rule_name=rule_name, priority=priority)

        return None


supported_label_types = [IsAutheliaLabel, PolicyLabel, PriorityLabel]


@dataclasses.dataclass
class RawContainer:
    container: DockerContainer
    name: str
    labels: dict[str, str]


@dataclasses.dataclass
class ParsedContainer:
    container: DockerContainer
    name: str
    is_authelia: bool
    labels: list[RuleLabel]

    @classmethod
    def from_raw(cls, container: RawContainer) -> Self | None:
        all_labels = cls.parse_labels(container.labels)
        if len(all_labels) == 0:
            return None

        is_authelia = any(isinstance(label, IsAutheliaLabel) for label in all_labels)
        rule_labels = [label for label in all_labels if isinstance(label, RuleLabel)]
        return cls(
            container=container.container,
            name=container.name,
            is_authelia=is_authelia,
            labels=rule_labels,
        )

    @staticmethod
    def parse_labels(raw_labels: dict[str, str]) -> list[LabelBase]:
        return [
            label_object
            for label_key, label_value in raw_labels.items()
            for label_type in supported_label_types
            if (label_object := label_type.try_parse(label_key, label_value))
            is not None
        ]


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
) -> list[RawContainer]:
    # TODO: handle DockerException
    return [
        RawContainer(container, container.name, container.labels)
        for container in docker_containers
    ]


def parse(
    raw_containers: list[RawContainer],
) -> list[ParsedContainer]:
    return [
        parsed_container
        for container in raw_containers
        if (parsed_container := ParsedContainer.from_raw(container)) is not None
    ]


if __name__ == '__main__':
    app()
