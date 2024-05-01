import abc
import collections
import dataclasses
import enum
import shutil
from pathlib import Path
from typing import Any, Self

from docker.models.containers import Container as DockerContainer
from loguru import logger
from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

from dl2ac import config


def _get_duplicates(values: list[Any]) -> list:
    counter = collections.Counter(values)
    duplicates = []
    for value, count in counter.most_common():
        if count <= 1:
            break

        duplicates.append(value)

    return duplicates


class AutheliaMethod(str, enum.Enum):
    GET = 'GET'
    HEAD = 'HEAD'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    CONNECT = 'CONNECT'
    OPTIONS = 'OPTIONS'
    TRACE = 'TRACE'
    PATCH = 'PATCH'
    PROPFIND = 'PROPFIND'
    PROPPATCH = 'PROPPATCH'
    MKCOL = 'MKCOL'
    COPY = 'COPY'
    MOVE = 'MOVE'
    LOCK = 'LOCK'
    UNLOCK = 'UNLOCK'


allowed_authelia_method_values = config.allowed_enum_values(AutheliaMethod)
logger.debug(f'Allowed Authelia Method Values: {allowed_authelia_method_values}')


@dataclasses.dataclass
class RawRule:
    methods: list[tuple[int, AutheliaMethod]] = dataclasses.field(default_factory=list)
    policies: list[config.AutheliaPolicy] = dataclasses.field(default_factory=list)
    ranks: list[int] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ParsedRule:
    name: str
    methods: list[AutheliaMethod]
    rank: int
    policy: config.AutheliaPolicy

    @classmethod
    def from_raw(
        cls,
        raw_rule: RawRule,
        rule_name: str,
        default_rule_policy: config.AutheliaPolicy,
    ) -> Self | None:
        # A single container cannot have duplicate label keys
        # because that's the design by docker.
        # However, different containers can have duplicate label keys.
        # So, we should still check for duplicates
        # because our program allows for definitions on any container.
        if not all(
            validation_function(values, rule_name, field_name)
            for validation_function, values, field_name in [
                (cls._validate_no_duplicate_indices, raw_rule.methods, 'methods'),
                (cls._validate_at_most_one, raw_rule.policies, 'policy'),
                (cls._validate_exactly_one, raw_rule.ranks, 'rank'),
            ]
        ):
            logger.warning(
                f'Rule `{rule_name}` is invalid because it has one or more invalid fields.'
                f' Skipping it. Please fix above issues to add it.'
            )
            return None

        # Sort methods by index (first value of tuple)
        methods = [method for _, method in sorted(raw_rule.methods)]

        # We have ensured that the lists have exactly at most one unique value,
        # so we can safely access it with [0] if it exists.
        policy = (
            raw_rule.policies[0] if len(raw_rule.policies) == 1 else default_rule_policy
        )
        rank = raw_rule.ranks[0]
        return cls(
            name=rule_name,
            methods=methods,
            policy=policy,
            rank=rank,
        )

    @staticmethod
    def _validate_at_most_one(
        values: list[Any], rule_name: str, field_name: str
    ) -> bool:
        if len(set(values)) > 1:
            logger.warning(
                f'Rule `{rule_name}`: Found multiple values for field `{field_name}`.'
                + f' {values=}'
                + ' Only zero or one are allowed. Please remove others.'
            )
            return False

        return True

    @staticmethod
    def _validate_exactly_one(
        values: list[Any], rule_name: str, field_name: str
    ) -> bool:
        if len(set(values)) != 1:
            logger.warning(
                f'Rule `{rule_name}`: Found zero or multiple values for field `{field_name}`.'
                + f' {values=}'
                + ' Only exactly one is allowed. Please remove others.'
            )
            return False

        return True

    @staticmethod
    def _validate_no_duplicate_indices(
        values: list[tuple[int, Any]], rule_name: str, field_name: str
    ) -> bool:
        indices = [index for index, *args in values]
        duplicates = _get_duplicates(indices)

        if len(duplicates) > 0:
            logger.warning(
                f'Rule `{rule_name}`: Found duplicate indices for field `{field_name}`.'
                + f' {duplicates=}'
                + ' Only exactly one is allowed. Please remove others.'
            )
            return False

        return True


# Has no rank because the rank will determine its position in the containing list
@dataclasses.dataclass
class SortedRule:
    name: str
    methods: list[AutheliaMethod]
    policy: config.AutheliaPolicy


@dataclasses.dataclass
class AccessControl:
    default_policy: config.AutheliaPolicy
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
class MethodLabel(RuleLabel):
    index: int
    method: AutheliaMethod

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.methods.1': 'OPTIONS'
        # TODO: add option to use csv
        # TODO: add debug logging
        if match := config.METHODS_KEY_REGEX.match(label_key):
            rule_name = match.group(1)
            index_str = match.group(2)

            try:
                index = int(index_str)
            except ValueError:
                # TODO: add container id, container name, and label_key
                logger.warning(
                    f'Invalid index value found, cannot parse `{index_str}` as int.'
                )
                return None

            try:
                method = AutheliaMethod[label_value.upper()]
            except KeyError:
                # TODO: add container id, container name, and label_key
                logger.warning(
                    f'Invalid method value found, cannot parse `{label_value}` as a method.'
                    f' Must be one of [{allowed_authelia_method_values}].'
                )
                return None

            return cls(rule_name=rule_name, index=index, method=method)

        return None

    def add_self_to(self, raw_rule: RawRule) -> None:
        raw_rule.methods.append((self.index, self.method))


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
class RankLabel(RuleLabel):
    rank: int

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.rank': '20'
        # TODO: add debug logging
        if match := config.RANK_KEY_REGEX.match(label_key):
            rule_name = match.group(1)

            try:
                rank = int(label_value)
            except ValueError:
                # TODO: add container id, container name, and label_key
                logger.warning(
                    f'Invalid rank value found, cannot parse `{label_value}` as int.'
                )
                return None

            return cls(rule_name=rule_name, rank=rank)

        return None

    def add_self_to(self, raw_rule: RawRule) -> None:
        raw_rule.ranks.append(self.rank)


supported_label_types = [IsAutheliaLabel, MethodLabel, PolicyLabel, RankLabel]


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
        logger.debug(f'{all_labels=}')
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


def has_authelia_containers(parsed_containers: list[ParsedContainer]) -> bool:
    return any(container.is_authelia for container in parsed_containers)


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

    ranks = [parsed_rule.rank for parsed_rule in parsed_rules]
    duplicates = _get_duplicates(ranks)
    if len(duplicates) > 0:
        logger.warning(
            'Found multiple rules with the same rank.'
            + f' {duplicates=}'
            + ' This might cause frequent Authelia restarts.'
            + ' Please ensure each rank is only set once.'
        )

    parsed_rules.sort(key=lambda rule: (rule.rank, rule.name))
    return [
        SortedRule(
            name=parsed_rule.name,
            methods=parsed_rule.methods,
            policy=parsed_rule.policy,
        )
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
        logger.error(f'Config file at `{str(config_file)}` does not exist')
        exit(3)

    if not backup_config_file.exists():
        logger.info(
            'Backup file does not exist.'
            + f' Creating one at `{str(backup_config_file)}`'
        )
        shutil.copyfile(str(config_file), str(backup_config_file))

    yaml = StringYaml()
    logger.debug(f'Reading config at `{str(config_file)}`')
    with open(config_file, 'r') as file:
        try:
            authelia_config = yaml.load(file)
        except Exception as exception:
            logger.error(
                f'Exception occurred while reading config file `{str(config_file)}`: {exception}'
            )
            exit(4)

    # logger.debug(f'Read config:\n{yaml.dump(authelia_config)}')
    authelia_config[config.UPDATE_YAML_KEY] = access_control_data
    # logger.debug(f'Updated config:\n{yaml.dump(authelia_config)}')

    logger.info(f'Writing config to `{str(config_file)}`')
    with open(config_file, 'w') as file:
        yaml.dump(authelia_config, file)


def write_access_control_data(access_control_data: dict, rules_file: Path) -> None:
    yaml = StringYaml()
    logger.debug(f'Writing rules to `{str(rules_file)}`')
    with open(rules_file, 'w') as file:
        yaml.dump(access_control_data, file)


def restart_containers(parsed_containers: list[ParsedContainer]) -> None:
    logger.debug('Restarting Authelia containers...')
    for container in parsed_containers:
        if container.is_authelia:
            logger.debug(f'Restarting `{container.name}`...')
            container.docker_container.restart()

    logger.info('Finished restarting Authelia containers.')


def enum_as_value_factory(data: list[tuple[str, Any]]) -> dict[str, Any]:
    def convert_value(obj: Any) -> Any:
        if isinstance(obj, enum.Enum):
            return obj.value
        elif isinstance(obj, list):
            # Lists should already be recursed into according to
            # https://docs.python.org/3.12/library/dataclasses.html#dataclasses.asdict
            # So, not sure why this branch is necessary here.
            # But without it, the result is incorrect.
            # rules.methods would be list[enum.Enum],
            # but we want it to be list[str]
            return [convert_value(item) for item in obj]

        return obj

    return dict((k, convert_value(v)) for k, v in data)


class StringYaml(YAML):
    def __init__(self) -> None:
        # Use the RoundTrip option to ensure that the config that we write
        # is most similar to the version we read.
        # This should preserve comments, order and other features.
        # This way, our program only makes minimal changes to the configuration.
        super().__init__(typ='rt')

        # Make sure that various strings in the original config file
        # such as secrets keep their quotation marks.
        # Unfortunately, this does not add quotation marks
        # to our own object AccessControl.
        # To do that, we would have to wrap each string in a
        # `SingleQuotedScalarString` object.
        # See https://stackoverflow.com/a/39263202
        self.preserve_quotes = True

    def dump(self, data, stream=None, **kw):
        # See https://yaml.readthedocs.io/en/latest/example/#output-of-dump-as-a-string
        inefficient = False
        if stream is None:
            inefficient = True
            stream = StringIO()

        YAML.dump(self, data, stream, **kw)
        if inefficient:
            return stream.getvalue()
