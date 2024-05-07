import abc
import dataclasses
import enum
import inspect
from typing import Any, ClassVar, Generic, Self, TypeVar

from loguru import logger

from dl2ac import config, parsers


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


class AutheliaOperator(str, enum.Enum):
    EQUAL = 'equal'
    NOT_EQUAL = 'not equal'
    PRESENT = 'present'
    ABSENT = 'absent'
    PATTERN = 'pattern'
    NOT_PATTERN = 'not pattern'


allowed_authelia_operator_values = config.allowed_enum_values(AutheliaOperator)
logger.debug(f'Allowed Authelia Operator Values: {allowed_authelia_operator_values}')


class ParsedLabel(abc.ABC):
    registered_parsable_label_types: ClassVar[list[type[Self]]] = []

    def __init_subclass__(cls, **kwargs: dict[str, Any]) -> None:
        super().__init_subclass__(**kwargs)
        # Automatically add every subclass that is not abstract to the list of supported types.
        # When parsing labels, every registered type will be tried out (try_parse).
        if not inspect.isabstract(cls):
            ParsedLabel.registered_parsable_label_types.append(cls)

    @classmethod
    @abc.abstractmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        pass

    @abc.abstractmethod
    def to_parsable_strings(self) -> tuple[str, str]:
        pass


@dataclasses.dataclass
class IsAutheliaLabel(ParsedLabel):
    is_authelia: bool

    label_key_parser: ClassVar[parsers.Parser[bool]] = parsers.RuleStringParser(
        rule_string=config.IS_AUTHELIA_KEY
    )
    label_value_parser: ClassVar[parsers.Parser[bool]] = parsers.BoolParser(
        'is_authelia'
    )

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.is-authelia': true
        label_key_data: bool | None = cls.label_key_parser.from_str(label_key)
        if label_key_data is None:
            return None

        if not label_key_data:
            logger.error(
                'Unfamiliar condition occurred:'
                + ' label_key_data should be True or None,'
                + f' but is {label_key_data=}. Please report this error.'
            )
            return None

        label_value_data: bool | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        is_authelia = label_value_data
        return cls(is_authelia=is_authelia)

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.IS_AUTHELIA_KEY
        label_value = str(self.is_authelia)
        return label_key, label_value


@dataclasses.dataclass
class TraefikRouterLabel(ParsedLabel):
    traefik_router_name: str
    domain: str

    label_key_parser: ClassVar[parsers.Parser[str]] = parsers.RegexParser(
        regex=config.TRAEFIK_ROUTER_KEY_REGEX, group_name='router_name'
    )
    label_value_parser: ClassVar[parsers.Parser[str]] = parsers.RegexParser(
        regex=config.TRAEFIK_ROUTER_VALUE_REGEX, group_name='domain'
    )

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'traefik.http.routers.whoami.rule': 'Host(`whoami.example.com`)'
        label_key_data: str | None = cls.label_key_parser.from_str(label_key)
        if label_key_data is None:
            return None

        label_value_data: str | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        router_name = label_key_data
        domain = label_value_data
        return cls(
            traefik_router_name=router_name,
            domain=domain,
        )

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.TRAEFIK_ROUTER_KEY_FORMAT.format(
            router_name=self.traefik_router_name,
        )
        label_value = config.TRAEFIK_ROUTER_VALUE_FORMAT.format(
            domain=self.domain,
        )
        return label_key, label_value


LabelDataType = TypeVar('LabelDataType')


@dataclasses.dataclass
class ResolvedRuleLabel(Generic[LabelDataType], abc.ABC):
    rule_name: str

    @abc.abstractmethod
    def to_data(self) -> LabelDataType:
        pass


@dataclasses.dataclass
class RawRuleLabel(ParsedLabel, abc.ABC):
    rule_name: str

    @abc.abstractmethod
    def resolve(
        self, raw_rule_labels: list['RawRuleLabel'], other_labels: list[ParsedLabel]
    ) -> 'ResolvedRuleLabel[Any] | None':
        # This method is used to convert
        # DomainAddTraefikLabel and TraefikRouterLabel to a DomainFromTraefikLabel
        # And QueryKeyLabel, QueryOperatorLabel, and QueryValueLabel to a QueryLabel
        pass


@dataclasses.dataclass
class DomainLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, str]]):
    # See https://www.authelia.com/configuration/security/access-control/#domain
    index: int
    domain: str

    label_key_parser: ClassVar[parsers.Parser[tuple[str, int]]] = (
        parsers.RuleWithOneIndexRegexParser(regex=config.DOMAIN_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[str]] = parsers.StringParser()

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.domain.1': '*.example.com'
        label_key_data: tuple[str, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: str | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        rule_name, index = label_key_data
        domain = label_value_data
        return cls(rule_name=rule_name, index=index, domain=domain)

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.DOMAIN_KEY_FORMAT.format(
            rule_name=self.rule_name,
            index=self.index,
        )
        label_value = self.domain
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        return self

    def to_data(self) -> tuple[int, str]:
        return self.index, self.domain


@dataclasses.dataclass
class DomainFromTraefikLabel(ResolvedRuleLabel[tuple[int, str]]):
    index: int
    domain: str

    def to_data(self) -> tuple[int, str]:
        return self.index, self.domain


@dataclasses.dataclass
class DomainAddTraefikLabel(RawRuleLabel):
    index: int
    traefik_router_name: str

    label_key_parser: ClassVar[parsers.Parser[tuple[str, int]]] = (
        parsers.RuleWithOneIndexRegexParser(regex=config.DOMAIN_ADD_TRAEFIK_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[str]] = parsers.StringParser()

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.domain_traefik.1': 'whoami'
        label_key_data: tuple[str, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: str | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        rule_name, index = label_key_data
        traefik_router_name = label_value_data
        return cls(
            rule_name=rule_name, index=index, traefik_router_name=traefik_router_name
        )

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.DOMAIN_ADD_TRAEFIK_KEY_FORMAT.format(
            rule_name=self.rule_name,
            index=self.index,
        )
        label_value = self.traefik_router_name
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> DomainFromTraefikLabel | None:
        # Converts DomainAddTraefikLabel and TraefikRouterLabel to a DomainFromTraefikLabel
        domains = [
            label.domain
            for label in other_labels
            if isinstance(label, TraefikRouterLabel)
            and label.traefik_router_name == self.traefik_router_name
        ]
        domains_set = set(domains)
        n_domains = len(domains_set)
        if n_domains == 0:
            traefik_router_labels = [
                label for label in other_labels if isinstance(label, TraefikRouterLabel)
            ]
            # TODO: add container id etc.
            logger.warning(
                f'Skipping adding domain from traefik ({self=}) because'
                + ' cannot find traefik router to dl2ac rule.'
                + ' Please make sure that exactly one traefik router exists'
                + ' by either creating a new traefik router'
                + " or changing this label's traefik router name."
                + f' {traefik_router_labels=}'
            )
            return None
        elif n_domains > 1:
            traefik_router_labels = [
                label for label in other_labels if isinstance(label, TraefikRouterLabel)
            ]
            # TODO: add container id etc.
            logger.warning(
                f'Skipping adding domain from traefik ({self=}) because'
                + ' found multiple values for this traefik router.'
                + ' Please make sure that exactly one unique domain for this traefik router exists'
                + ' by removing other traefik routers'
                + ' or changing this traefik router name.'
                + f' {domains_set=}, {traefik_router_labels=}'
            )
            return None

        domain = domains[0]
        return DomainFromTraefikLabel(
            rule_name=self.rule_name, index=self.index, domain=domain
        )


@dataclasses.dataclass
class DomainRegexLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, str]]):
    # See https://www.authelia.com/configuration/security/access-control/#domain_regex
    index: int
    domain_regex: str

    label_key_parser: ClassVar[parsers.Parser[tuple[str, int]]] = (
        parsers.RuleWithOneIndexRegexParser(regex=config.DOMAIN_REGEX_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[str]] = parsers.StringParser()

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.domain_regex.1': '^user-(?P<User>\w+)\.example\.com$'
        label_key_data: tuple[str, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: str | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        rule_name, index = label_key_data
        domain_regex = label_value_data
        return cls(rule_name=rule_name, index=index, domain_regex=domain_regex)

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.DOMAIN_REGEX_KEY_FORMAT.format(
            rule_name=self.rule_name,
            index=self.index,
        )
        label_value = self.domain_regex
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        return self

    def to_data(self) -> tuple[int, str]:
        return self.index, self.domain_regex


@dataclasses.dataclass
class MethodsLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, AutheliaMethod]]):
    # See https://www.authelia.com/configuration/security/access-control/#methods
    index: int
    method: AutheliaMethod

    label_key_parser: ClassVar[parsers.Parser[tuple[str, int]]] = (
        parsers.RuleWithOneIndexRegexParser(regex=config.METHODS_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[AutheliaMethod]] = parsers.EnumParser(
        field_name='methods',
        enum_type=AutheliaMethod,
        enum_name='methods',
        allowed_values=allowed_authelia_method_values,
    )

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.methods.1': 'OPTIONS'
        label_key_data: tuple[str, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: AutheliaMethod | None = cls.label_value_parser.from_str(
            label_value
        )
        if label_value_data is None:
            return None

        rule_name, index = label_key_data
        method = label_value_data
        return cls(rule_name=rule_name, index=index, method=method)

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.METHODS_KEY_FORMAT.format(
            rule_name=self.rule_name,
            index=self.index,
        )
        label_value = self.method.value
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        return self

    def to_data(self) -> tuple[int, AutheliaMethod]:
        return self.index, self.method


@dataclasses.dataclass
class PolicyLabel(RawRuleLabel, ResolvedRuleLabel[config.AutheliaPolicy]):
    # See https://www.authelia.com/configuration/security/access-control/#policy
    policy: config.AutheliaPolicy

    label_key_parser: ClassVar[parsers.Parser[str]] = parsers.RuleRegexParser(
        regex=config.POLICY_KEY_REGEX
    )
    label_value_parser: ClassVar[parsers.Parser[config.AutheliaPolicy]] = (
        parsers.EnumParser(
            field_name='policy',
            enum_type=config.AutheliaPolicy,
            enum_name='policy',
            allowed_values=config.allowed_authelia_policy_values,
        )
    )

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.policy': 'one_factor'
        label_key_data: str | None = cls.label_key_parser.from_str(label_key)
        if label_key_data is None:
            return None

        label_value_data: config.AutheliaPolicy | None = (
            cls.label_value_parser.from_str(label_value)
        )
        if label_value_data is None:
            return None

        rule_name = label_key_data
        policy = label_value_data
        return cls(rule_name=rule_name, policy=policy)

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.POLICY_KEY_FORMAT.format(rule_name=self.rule_name)
        label_value = self.policy.value
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        return self

    def to_data(self) -> config.AutheliaPolicy:
        return self.policy


@dataclasses.dataclass
class QueryObject:
    key: str
    operator: AutheliaOperator | None
    value: str | None


@dataclasses.dataclass
class QueryLabel(ResolvedRuleLabel[tuple[int, int, QueryObject]]):
    # See https://www.authelia.com/configuration/security/access-control/#query
    outer_index: int
    inner_index: int
    query: QueryObject

    def to_data(self) -> tuple[int, int, QueryObject]:
        return self.outer_index, self.inner_index, self.query


@dataclasses.dataclass
class QueryKeyLabel(RawRuleLabel):
    outer_index: int
    inner_index: int
    key: str

    label_key_parser: ClassVar[parsers.Parser[tuple[str, int, int]]] = (
        parsers.RuleWithTwoIndicesRegexParser(regex=config.QUERY_KEY_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[str]] = parsers.StringParser()

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.query.1.1.key': 'random'
        label_key_data: tuple[str, int, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: str | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        rule_name, outer_index, inner_index = label_key_data
        key = label_value_data
        return cls(
            rule_name=rule_name,
            outer_index=outer_index,
            inner_index=inner_index,
            key=key,
        )

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.QUERY_KEY_KEY_FORMAT.format(
            rule_name=self.rule_name,
            outer_index=self.outer_index,
            inner_index=self.inner_index,
        )
        label_value = self.key
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> QueryLabel | None:
        # Converts QueryKeyLabel, QueryOperatorLabel, and QueryValueLabel to a QueryLabel

        # Find all operators for this query
        # There should be at most one unique value
        operators = [
            label.operator
            for label in raw_rule_labels
            if isinstance(label, QueryOperatorLabel)
            and label.rule_name == self.rule_name
            and label.outer_index == self.outer_index
            and label.inner_index == self.inner_index
        ]
        operators_set = set(operators)
        n_operators = len(operators_set)
        if n_operators > 1:
            operator_labels = [
                label for label in other_labels if isinstance(label, TraefikRouterLabel)
            ]
            # TODO: fix log
            # TODO: add container id etc.
            logger.warning(
                f'Skipping query ({self=}) because'
                + ' found multiple operators for this query.'
                + f' {operators_set=}'
                + ' Please make sure that exactly one unique operator'
                + ' for this query by removing other operators.'
                + f' {operators_set=}, {operator_labels=}'
            )
            return None

        # Find all values for this query
        # There should be at most one unique value
        values = [
            label.value
            for label in raw_rule_labels
            if isinstance(label, QueryValueLabel)
            and label.rule_name == self.rule_name
            and label.outer_index == self.outer_index
            and label.inner_index == self.inner_index
        ]
        values_set = set(values)
        n_values = len(values_set)
        if n_values > 1:
            value_labels = [
                label for label in other_labels if isinstance(label, QueryValueLabel)
            ]
            # TODO: fix log
            # TODO: add container id etc.
            logger.warning(
                f'Skipping query ({self=}) because'
                + ' found multiple values for this query.'
                + f' {values_set=}'
                + ' Please make sure that exactly one unique value'
                + ' for this query by removing other values.'
                + f' {operators_set=}, {value_labels=}'
            )
            return None

        # For omitting rules, see https://www.authelia.com/configuration/security/access-control/#query
        # key: required
        # value: This is required unless the operator is absent or present
        # operator: If key and value are specified this defaults to equal,
        # otherwise if key is specified it defaults to present.
        operator = None
        value = None
        logger.debug(f'{self=}, {operators=}, {values=}')
        if n_operators == 0:
            if n_values == 1:
                # operator = AutheliaOperator.EQUAL
                value = values[0]
            else:
                # operator = AutheliaOperator.PRESENT
                pass
        else:
            operator = operators[0]
            if operator == AutheliaOperator.ABSENT:
                if n_values == 1:
                    return None

                # value = None
            elif operator == AutheliaOperator.PRESENT:
                if n_values == 1:
                    return None

                # value = None
            elif operator == AutheliaOperator.EQUAL:
                if n_values == 0:
                    return None

                value = values[0]

        query_object = QueryObject(
            key=self.key,
            operator=operator,
            value=value,
        )
        return QueryLabel(
            rule_name=self.rule_name,
            outer_index=self.outer_index,
            inner_index=self.inner_index,
            query=query_object,
        )


@dataclasses.dataclass
class QueryOperatorLabel(RawRuleLabel):
    outer_index: int
    inner_index: int
    operator: AutheliaOperator

    label_key_parser: ClassVar[parsers.Parser[tuple[str, int, int]]] = (
        parsers.RuleWithTwoIndicesRegexParser(regex=config.QUERY_OPERATOR_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[AutheliaOperator]] = parsers.EnumParser(
        field_name='operator',
        enum_type=AutheliaOperator,
        enum_name='operator',
        allowed_values=allowed_authelia_operator_values,
    )

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.query.1.1.operator': 'not pattern'
        label_key_data: tuple[str, int, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: AutheliaOperator | None = cls.label_value_parser.from_str(
            label_value
        )
        if label_value_data is None:
            return None

        rule_name, outer_index, inner_index = label_key_data
        operator = label_value_data
        return cls(
            rule_name=rule_name,
            outer_index=outer_index,
            inner_index=inner_index,
            operator=operator,
        )

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.QUERY_OPERATOR_KEY_FORMAT.format(
            rule_name=self.rule_name,
            outer_index=self.outer_index,
            inner_index=self.inner_index,
        )
        label_value = self.operator.value
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        # todo: explain
        return None


@dataclasses.dataclass
class QueryValueLabel(RawRuleLabel):
    outer_index: int
    inner_index: int
    value: str

    label_key_parser: ClassVar[parsers.Parser[tuple[str, int, int]]] = (
        parsers.RuleWithTwoIndicesRegexParser(regex=config.QUERY_VALUE_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[str]] = parsers.StringParser()

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.query.1.1.value': '^(1|2)$'
        label_key_data: tuple[str, int, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: str | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        rule_name, outer_index, inner_index = label_key_data
        value = label_value_data
        return cls(
            rule_name=rule_name,
            outer_index=outer_index,
            inner_index=inner_index,
            value=value,
        )

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.QUERY_VALUE_KEY_FORMAT.format(
            rule_name=self.rule_name,
            outer_index=self.outer_index,
            inner_index=self.inner_index,
        )
        label_value = self.value
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        # todo: explain
        return None


@dataclasses.dataclass
class RankLabel(RawRuleLabel, ResolvedRuleLabel[int]):
    rank: int

    label_key_parser: ClassVar[parsers.Parser[str]] = parsers.RuleRegexParser(
        regex=config.RANK_KEY_REGEX
    )
    label_value_parser: ClassVar[parsers.Parser[int]] = parsers.IntParser(
        field_name='rank',
    )

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.rank': '20'
        label_key_data: str | None = cls.label_key_parser.from_str(label_key)
        if label_key_data is None:
            return None

        label_value_data: int | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        rule_name = label_key_data
        rank = label_value_data
        return cls(rule_name=rule_name, rank=rank)

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.RANK_KEY_FORMAT.format(
            rule_name=self.rule_name,
        )
        label_value = str(self.rank)
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        return self

    def to_data(self) -> int:
        return self.rank


@dataclasses.dataclass
class ResourcesLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, str]]):
    # See https://www.authelia.com/configuration/security/access-control/#resources
    index: int
    resource: str

    label_key_parser: ClassVar[parsers.Parser[tuple[str, int]]] = (
        parsers.RuleWithOneIndexRegexParser(regex=config.RESOURCES_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[str]] = parsers.StringParser()

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.resources.1': '^/api([/?].*)?$'
        label_key_data: tuple[str, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: str | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        rule_name, index = label_key_data
        resource = label_value_data
        return cls(rule_name=rule_name, index=index, resource=resource)

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.RESOURCES_KEY_FORMAT.format(
            rule_name=self.rule_name,
            index=self.index,
        )
        label_value = str(self.resource)
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        return self

    def to_data(self) -> tuple[int, str]:
        return self.index, self.resource


@dataclasses.dataclass
class SubjectLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, int, str]]):
    # See https://www.authelia.com/configuration/security/access-control/#subject
    outer_index: int
    inner_index: int
    subject: str

    # TODO: add option to use csv
    # TODO: add validation for `user:`, `group:` and `oauth2:client:`
    label_key_parser: ClassVar[parsers.Parser[tuple[str, int, int]]] = (
        parsers.RuleWithTwoIndicesRegexParser(regex=config.SUBJECT_KEY_REGEX)
    )
    label_value_parser: ClassVar[parsers.Parser[str]] = parsers.StringParser()

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.subjects.1.1': 'user:john'
        label_key_data: tuple[str, int, int] | None = cls.label_key_parser.from_str(
            label_key
        )
        if label_key_data is None:
            return None

        label_value_data: str | None = cls.label_value_parser.from_str(label_value)
        if label_value_data is None:
            return None

        rule_name, outer_index, inner_index = label_key_data
        subject = label_value_data
        return cls(
            rule_name=rule_name,
            outer_index=outer_index,
            inner_index=inner_index,
            subject=subject,
        )

    def to_parsable_strings(self) -> tuple[str, str]:
        label_key = config.SUBJECT_KEY_FORMAT.format(
            rule_name=self.rule_name,
            outer_index=self.outer_index,
            inner_index=self.inner_index,
        )
        label_value = str(self.subject)
        return label_key, label_value

    def resolve(
        self, raw_rule_labels: list[RawRuleLabel], other_labels: list[ParsedLabel]
    ) -> ResolvedRuleLabel[Any] | None:
        return self

    def to_data(self) -> tuple[int, int, str]:
        return self.outer_index, self.inner_index, self.subject


def resolve(
    raw_rule_labels: list[RawRuleLabel],
    other_labels: list[ParsedLabel],
) -> list[ResolvedRuleLabel[Any]]:
    return [
        resolved_label
        for label in raw_rule_labels
        if (resolved_label := label.resolve(raw_rule_labels, other_labels)) is not None
    ]
