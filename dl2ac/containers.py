import dataclasses
from typing import Self

from docker.models.containers import Container as DockerContainer
from loguru import logger

from dl2ac import labels as dl2ac_labels


@dataclasses.dataclass
class RawContainer:
    docker_container: DockerContainer
    name: str
    labels: dict[str, str]


@dataclasses.dataclass
class ParsedContainer:
    docker_container: DockerContainer
    name: str
    is_authelia: bool
    labels: list[dl2ac_labels.RuleLabel]

    @classmethod
    def from_raw(cls, raw_container: RawContainer) -> Self | None:
        all_labels = cls.parse_labels(raw_container.labels)
        logger.debug(f'{raw_container=}, {all_labels=}')
        if len(all_labels) == 0:
            return None

        is_authelia = any(
            isinstance(label, dl2ac_labels.IsAutheliaLabel) and label.is_authelia
            for label in all_labels
        )
        rule_labels = [
            label for label in all_labels if isinstance(label, dl2ac_labels.RuleLabel)
        ]
        return cls(
            docker_container=raw_container.docker_container,
            name=raw_container.name,
            is_authelia=is_authelia,
            labels=rule_labels,
        )

    @staticmethod
    def parse_labels(raw_labels: dict[str, str]) -> list[dl2ac_labels.LabelBase]:
        return [
            label_object
            for label_key, label_value in raw_labels.items()
            for label_type in dl2ac_labels.supported_label_types
            if (label_object := label_type.try_parse(label_key, label_value))
            is not None
        ]


def load_containers(
    docker_containers: list[DockerContainer],
) -> list[RawContainer]:
    # TODO: handle DockerException
    return [
        RawContainer(
            docker_container=docker_container,
            name=docker_container.name,
            labels=docker_container.labels,
        )
        for docker_container in docker_containers
    ]


def load_rules(
    parsed_containers: list[ParsedContainer],
) -> list[dl2ac_labels.RuleLabel]:
    return [
        label
        for parsed_container in parsed_containers
        for label in parsed_container.labels
    ]


def parse_containers(
    raw_containers: list[RawContainer],
) -> list[ParsedContainer]:
    return [
        parsed_container
        for raw_container in raw_containers
        if (parsed_container := ParsedContainer.from_raw(raw_container)) is not None
    ]


def has_authelia_containers(parsed_containers: list[ParsedContainer]) -> bool:
    return any(container.is_authelia for container in parsed_containers)


def restart_containers(parsed_containers: list[ParsedContainer]) -> None:
    logger.debug('Restarting Authelia containers...')
    for container in parsed_containers:
        if container.is_authelia:
            logger.debug(f'Restarting `{container.name}`...')
            container.docker_container.restart()

    logger.info('Finished restarting Authelia containers.')
