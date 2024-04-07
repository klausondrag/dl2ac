import abc
import dataclasses
from typing import Self


from docker.models.containers import Container as DockerContainer
from loguru import logger

from dl2ac import config


@dataclasses.dataclass
class RawRule:
    policies: list[config.AutheliaPolicy] = dataclasses.field(default_factory=list)
    priorities: list[int] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ParsedRule:
    name: str
    policy: config.AutheliaPolicy
    priority: int

    @classmethod
    def from_raw(cls, raw_rule: RawRule, rule_name: str) -> Self | None:
        if not all(
            cls._validate(values, rule_name, field_name)
            for values, field_name in [
                (raw_rule.policies, 'policy'),
                (raw_rule.priorities, 'priority'),
            ]
        ):
            logger.warning(
                f'Rule {rule_name} is invalid because it has one or more invalid fields.'
                f' Skipping it. Please fix above issues to add it.'
            )
            return None

        # We have ensured that the lists have exactly one unique value,
        # so we can safely access it with [0].
        return cls(
            name=rule_name,
            policy=raw_rule.policies[0],
            priority=raw_rule.priorities[0],
        )

    @staticmethod
    def _validate(values: list, rule_name: str, field_name: str) -> bool:
        if len(set(values)) != 1:
            logger.warning(
                f'Rule {rule_name}: Found multiple values for field {field_name}. {values}'
                f' Only one is allowed. Please remove others.'
            )
            return False

        return True


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
        # TODO: add debug logging
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

    @abc.abstractmethod
    def add_self_to(self, raw_rule: RawRule) -> None:
        pass


@dataclasses.dataclass
class PolicyLabel(RuleLabel):
    policy: config.AutheliaPolicy

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.policy': 'one_factor'
        # TODO: add debug logging
        if match := config.POLICY_KEY_REGEX.match(label_key):
            rule_name = match.group(1)

            try:
                policy = config.AutheliaPolicy[label_value.upper()]
            except KeyError:
                # TODO: add container id, container name, and label_key
                logger.warning(
                    f'Invalid policy value found, cannot parse `{label_value}` as a policy.'
                    f' Must be one of [{config.allowed_authelia_policy_values}].'
                )
                return None

            return cls(rule_name=rule_name, policy=policy)

        return None

    def add_self_to(self, raw_rule: RawRule) -> None:
        raw_rule.policies.append(self.policy)


@dataclasses.dataclass
class PriorityLabel(RuleLabel):
    priority: int

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.priority': '20'
        # TODO: add debug logging
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

    def add_self_to(self, raw_rule: RawRule) -> None:
        raw_rule.priorities.append(self.priority)


supported_label_types = [IsAutheliaLabel, PolicyLabel, PriorityLabel]


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
    labels: list[RuleLabel]

    @classmethod
    def from_raw(cls, raw_container: RawContainer) -> Self | None:
        all_labels = cls.parse_labels(raw_container.labels)
        if len(all_labels) == 0:
            return None

        is_authelia = any(isinstance(label, IsAutheliaLabel) for label in all_labels)
        rule_labels = [label for label in all_labels if isinstance(label, RuleLabel)]
        return cls(
            docker_container=raw_container.docker_container,
            name=raw_container.name,
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
