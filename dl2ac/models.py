import abc
import collections
import dataclasses
import enum
import shutil
from pathlib import Path
from typing import Self

from docker.models.containers import Container as DockerContainer
from loguru import logger
from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

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
    def from_raw(
        cls,
        raw_rule: RawRule,
        rule_name: str,
        default_rule_policy: config.AutheliaPolicy,
    ) -> Self | None:
        if not all(
            validation_function(values, rule_name, field_name)
            for validation_function, values, field_name in [
                (cls._validate_at_most_one, raw_rule.policies, 'policy'),
                (cls._validate_exactly_one, raw_rule.priorities, 'priority'),
            ]
        ):
            logger.warning(
                f'Rule {rule_name} is invalid because it has one or more invalid fields.'
                f' Skipping it. Please fix above issues to add it.'
            )
            return None

        # We have ensured that the lists have exactly at most one unique value,
        # so we can safely access it with [0] if it exists.
        policy = (
            raw_rule.policies[0] if len(raw_rule.policies) == 1 else default_rule_policy
        )
        priority = raw_rule.priorities[0]
        return cls(
            name=rule_name,
            policy=policy,
            priority=priority,
        )

    @staticmethod
    def _validate_at_most_one(values: list, rule_name: str, field_name: str) -> bool:
        if len(set(values)) > 1:
            logger.warning(
                f'Rule {rule_name}: Found multiple values for field {field_name}. {values}'
                f' Only zero or one are allowed. Please remove others.'
            )
            return False

        return True

    @staticmethod
    def _validate_exactly_one(values: list, rule_name: str, field_name: str) -> bool:
        if len(set(values)) != 1:
            logger.warning(
                f'Rule {rule_name}: Found multiple values for field {field_name}. {values}'
                f' Only exactly one is allowed. Please remove others.'
            )
            return False

        return True


# Has no priority because the priority will determine its position in the containing list
@dataclasses.dataclass
class SortedRule:
    name: str
    policy: config.AutheliaPolicy


@dataclasses.dataclass
class AccessControl:
    default_policy: str
    rules: list[SortedRule]


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


def parse_containers(
    raw_containers: list[RawContainer],
) -> list[ParsedContainer]:
    return [
        parsed_container
        for raw_container in raw_containers
        if (parsed_container := ParsedContainer.from_raw(raw_container)) is not None
    ]


def load_rules(
    parsed_containers: list[ParsedContainer],
) -> list[RuleLabel]:
    return [
        label
        for parsed_container in parsed_containers
        for label in parsed_container.labels
    ]


def parse_rules(
    label_list: list[RuleLabel],
    default_rule_policy: config.AutheliaPolicy,
) -> list[ParsedRule]:
    raw_rules: dict[str, RawRule] = collections.defaultdict(RawRule)
    for label in label_list:
        rule = raw_rules[label.rule_name]
        label.add_self_to(rule)

    parsed_rules = [
        parsed_rule
        for rule_name, rule in raw_rules.items()
        if (parsed_rule := ParsedRule.from_raw(rule, rule_name, default_rule_policy))
        is not None
    ]
    return parsed_rules


def sort_rules(parsed_rules: list[ParsedRule]) -> list[SortedRule]:
    if len(parsed_rules) == 0:
        return []

    priorities = [parsed_rule.priority for parsed_rule in parsed_rules]
    counter = collections.Counter(priorities)
    # most_common(1) returns a list of the most common element: [(priority, count)]
    # so [0][1] gets the count of the most common element
    if counter.most_common(1)[0][1] > 1:
        logger.warning(
            'Found multiple rules with the same priority.'
            ' This might cause frequent Authelia restarts.'
            ' Please ensure each priority is only set once.'
        )

    parsed_rules = sorted(parsed_rules, key=lambda rule: rule.priority)
    return [
        SortedRule(name=parsed_rule.name, policy=parsed_rule.policy)
        for parsed_rule in parsed_rules
    ]


def to_access_control(
    sorted_rules: list[SortedRule],
    default_authelia_policy: config.AutheliaPolicy,
) -> AccessControl:
    access_control = AccessControl(
        default_policy=default_authelia_policy,
        rules=sorted_rules,
    )

    return access_control


def write_config(
    access_control_data: dict, config_file: Path, backup_config_file: Path
) -> None:
    if not config_file.exists():
        logger.error(f'Config file at {str(config_file)} does not exist')
        exit(3)

    if not backup_config_file.exists():
        logger.info(
            'Backup file does not exist.'
            + f' Creating one at {str(backup_config_file)}'
        )
        shutil.copyfile(str(config_file), str(backup_config_file))

    yaml = StringYAML()
    logger.debug(f'Reading config at {str(config_file)}')
    with open(config_file, 'r') as file:
        try:
            authelia_config = yaml.load(file)
        except Exception as exception:
            logger.error(
                f'Exception occurred while reading config file {str(config_file)}: {exception}'
            )
            exit(4)

    # logger.debug(f'Read config:\n{yaml.dump(authelia_config)}')
    authelia_config[config.UPDATE_YAML_KEY] = access_control_data
    # logger.debug(f'Updated config:\n{yaml.dump(authelia_config)}')

    logger.info(f'Writing config to {str(config_file)}')
    with open(config_file, 'w') as file:
        yaml.dump(authelia_config, file)


def write_rules(rules: list[SortedRule], rules_file: Path) -> None:
    yaml = StringYAML()
    logger.debug(f'Writing rules to {str(rules_file)}')
    rules_as_dicts = [
        dataclasses.asdict(rule, dict_factory=enum_as_value_factory) for rule in rules
    ]
    with open(rules_file, 'w') as file:
        yaml.dump(rules_as_dicts, file)


def restart_containers(parsed_containers: list[ParsedContainer]):
    logger.debug('Restarting Authelia containers...')
    for container in parsed_containers:
        if container.is_authelia:
            logger.debug(f'Restarting {container.name}...')
            container.docker_container.restart()

    logger.info('Finished restarting Authelia containers.')


def enum_as_value_factory(data):
    def convert_value(obj):
        if isinstance(obj, enum.Enum):
            return obj.value

        return obj

    return dict((k, convert_value(v)) for k, v in data)


# See https://yaml.readthedocs.io/en/latest/example/#output-of-dump-as-a-string
class StringYAML(YAML):
    def dump(self, data, stream=None, **kw):
        inefficient = False
        if stream is None:
            inefficient = True
            stream = StringIO()

        YAML.dump(self, data, stream, **kw)
        if inefficient:
            return stream.getvalue()
