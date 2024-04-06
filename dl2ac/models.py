import abc
import dataclasses
import enum
from typing import Self


from docker.models.containers import Container as DockerContainer
from loguru import logger

from dl2ac import config


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
            label_key == config.IS_AUTHELIA_KEY
            and label_value.lower() == config.IS_AUTHELIA_VALUE
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
