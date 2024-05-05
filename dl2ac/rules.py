import collections
import dataclasses
import enum
import shutil
from pathlib import Path
from typing import Any, Self

from loguru import logger
from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

from dl2ac import config, labels


def _get_duplicates(values: list[Any]) -> list:
    counter = collections.Counter(values)
    duplicates = []
    for value, count in counter.most_common():
        if count <= 1:
            break

        duplicates.append(value)

    return duplicates


@dataclasses.dataclass
class RawRule:
    domain: list[tuple[int, str]] = dataclasses.field(default_factory=list)
    domain_from_traefik: list[tuple[int, str]] = dataclasses.field(default_factory=list)
    domain_regex: list[tuple[int, str]] = dataclasses.field(default_factory=list)
    methods: list[tuple[int, labels.AutheliaMethod]] = dataclasses.field(
        default_factory=list
    )
    policy: list[config.AutheliaPolicy] = dataclasses.field(default_factory=list)
    rank: list[int] = dataclasses.field(default_factory=list)
    resources: list[tuple[int, str]] = dataclasses.field(default_factory=list)
    subject: list[tuple[int, int, str]] = dataclasses.field(default_factory=list)

    def add(self, label: labels.ResolvedRuleLabel):
        data = label.to_data()
        match type(label):
            case labels.DomainLabel:
                self.domain.append(data)
            case labels.DomainFromTraefikLabel:
                self.domain_from_traefik.append(data)
            case labels.DomainRegexLabel:
                self.domain_regex.append(data)
            case labels.MethodsLabel:
                self.methods.append(data)
            case labels.PolicyLabel:
                self.policy.append(data)
            case labels.RankLabel:
                self.rank.append(data)
            case labels.ResourcesLabel:
                self.resources.append(data)
            case labels.SubjectLabel:
                self.subject.append(data)
            case _:
                logger.error(
                    f'Unknown label type: {type(label)=}, {label=}.'
                    + ' Please report this error.'
                )


@dataclasses.dataclass
class ParsedRule:
    name: str
    domain: list[str]
    domain_regex: list[str]
    methods: list[labels.AutheliaMethod]
    rank: int
    policy: config.AutheliaPolicy
    resources: list[str]
    subject: list[str | list[str]]

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
                (cls._validate_no_duplicate_first_index, raw_rule.domain, 'domain'),
                (
                    cls._validate_no_duplicate_first_index,
                    raw_rule.domain_from_traefik,
                    'domain.from_traefik',
                ),
                (
                    cls._validate_no_duplicate_first_index,
                    raw_rule.domain_regex,
                    'domain_regex',
                ),
                (cls._validate_no_duplicate_first_index, raw_rule.methods, 'methods'),
                (cls._validate_at_most_one, raw_rule.policy, 'policy'),
                (cls._validate_exactly_one, raw_rule.rank, 'rank'),
                (
                    cls._validate_no_duplicate_first_index,
                    raw_rule.resources,
                    'resources',
                ),
                (
                    cls._validate_no_duplicate_first_second_indices,
                    raw_rule.subject,
                    'subject',
                ),
            ]
        ):
            logger.warning(
                f'Rule `{rule_name}` is invalid because it has one or more invalid fields.'
                f' Skipping it. Please fix above issues to add it.'
            )
            return None

        # Sort domain by index (first value of tuple)
        domain = [domain for _, domain in sorted(raw_rule.domain)]

        # Sort domain by index (first value of tuple)
        domain_from_traefik = [
            domain for _, domain in sorted(raw_rule.domain_from_traefik)
        ]

        # Merge domain and domain_from_traefik
        domain.extend(domain_from_traefik)

        # Sort domain_regex by index (first value of tuple)
        domain_regex = [
            domain_regex for _, domain_regex in sorted(raw_rule.domain_regex)
        ]

        # Sort methods by index (first value of tuple)
        methods = [method for _, method in sorted(raw_rule.methods)]

        # We have ensured that the lists have exactly at most one unique value,
        # so we can safely access it with [0] if it exists.
        policy = (
            raw_rule.policy[0] if len(raw_rule.policy) == 1 else default_rule_policy
        )
        rank = raw_rule.rank[0]

        # Sort resources by index (first value of tuple)
        resources = [resource for _, resource in sorted(raw_rule.resources)]

        ordered_subject_dict: collections.defaultdict[
            int, collections.defaultdict[int, str]
        ] = collections.defaultdict(lambda: collections.defaultdict(str))
        for outer_index, inner_index, subject in raw_rule.subject:
            ordered_subject_dict[outer_index][inner_index] = subject

        ordered_subject_list: list[list[str]] = [
            [
                ordered_subject_dict[outer_index][inner_index]
                for inner_index in sorted(ordered_subject_dict[outer_index].keys())
            ]
            for outer_index in sorted(ordered_subject_dict.keys())
        ]

        simplified_subject_list: list[str | list[str]] = [
            outer_subject_list[0]
            if len(outer_subject_list) == 1
            else outer_subject_list
            for outer_subject_list in ordered_subject_list
        ]

        return cls(
            name=rule_name,
            domain=domain,
            domain_regex=domain_regex,
            methods=methods,
            policy=policy,
            rank=rank,
            resources=resources,
            subject=simplified_subject_list,
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
    def _validate_no_duplicate_first_index(
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

    @staticmethod
    def _validate_no_duplicate_first_second_indices(
        values: list[tuple[int, int, Any]], rule_name: str, field_name: str
    ) -> bool:
        indices = [
            (outer_index, inner_index) for outer_index, inner_index, *args in values
        ]
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
    domain: list[str]
    domain_regex: list[str]
    methods: list[labels.AutheliaMethod]
    policy: config.AutheliaPolicy
    resources: list[str]
    subject: list[str | list[str]]


@dataclasses.dataclass
class AccessControl:
    default_policy: config.AutheliaPolicy
    rules: list[SortedRule]


def parse_rules(
    label_list: list[labels.ResolvedRuleLabel],
    default_rule_policy: config.AutheliaPolicy,
) -> list[ParsedRule]:
    raw_rules: dict[str, RawRule] = collections.defaultdict(RawRule)
    for label in label_list:
        rule = raw_rules[label.rule_name]
        rule.add(label)

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
            domain=parsed_rule.domain,
            domain_regex=parsed_rule.domain_regex,
            methods=parsed_rule.methods,
            policy=parsed_rule.policy,
            resources=parsed_rule.resources,
            subject=parsed_rule.subject,
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
