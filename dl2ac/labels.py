import abc
import dataclasses
import enum
from typing import ClassVar, Generic, Self, TypeVar

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


class ParsedLabel(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
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
    def resolve(self, other_labels: list[ParsedLabel]) -> 'ResolvedRuleLabel | None':
        # This method is used to convert
        # DomainAddTraefikLabel and TraefikRouterLabel to a
        # DomainFromTraefikLabel
        pass


@dataclasses.dataclass
class DomainLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, str]]):
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

    def resolve(self, other_labels: list[ParsedLabel]) -> Self | None:
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
        # 'dl2ac.rules.one.domains.add_traefik.1': 'whoami'
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

    def resolve(self, other_labels: list[ParsedLabel]) -> DomainFromTraefikLabel | None:
        # This method is used to convert
        # DomainAddTraefikLabel and TraefikRouterLabel to a
        # DomainFromTraefikLabel
        domain = None
        for label in other_labels:
            if (
                isinstance(label, TraefikRouterLabel)
                and label.traefik_router_name == self.traefik_router_name
            ):
                domain = label.domain

        if domain is None:
            traefik_router_labels = [
                label for label in other_labels if isinstance(label, TraefikRouterLabel)
            ]
            # TODO: add container id etc.
            logger.warning(
                f'Cannot find traefik router to dl2ac rule {self=}. {traefik_router_labels=}'
            )
            return None

        return DomainFromTraefikLabel(
            rule_name=self.rule_name, index=self.index, domain=domain
        )


@dataclasses.dataclass
class DomainRegexLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, str]]):
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

    def resolve(self, other_labels: list[ParsedLabel]) -> Self | None:
        return self

    def to_data(self) -> tuple[int, str]:
        return self.index, self.domain_regex


@dataclasses.dataclass
class MethodsLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, AutheliaMethod]]):
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

    def resolve(self, other_labels: list[ParsedLabel]) -> Self | None:
        return self

    def to_data(self) -> tuple[int, AutheliaMethod]:
        return self.index, self.method


@dataclasses.dataclass
class PolicyLabel(RawRuleLabel, ResolvedRuleLabel[config.AutheliaPolicy]):
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

    def resolve(self, other_labels: list[ParsedLabel]) -> Self | None:
        return self

    def to_data(self) -> config.AutheliaPolicy:
        return self.policy


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

    def resolve(self, other_labels: list[ParsedLabel]) -> Self | None:
        return self

    def to_data(self) -> int:
        return self.rank


@dataclasses.dataclass
class ResourcesLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, str]]):
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

    def resolve(self, other_labels: list[ParsedLabel]) -> Self | None:
        return self

    def to_data(self) -> tuple[int, str]:
        return self.index, self.resource


@dataclasses.dataclass
class SubjectLabel(RawRuleLabel, ResolvedRuleLabel[tuple[int, int, str]]):
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

    def resolve(self, other_labels: list[ParsedLabel]) -> Self | None:
        return self

    def to_data(self) -> tuple[int, int, str]:
        return self.outer_index, self.inner_index, self.subject


supported_label_types: list[type[ParsedLabel]] = [
    IsAutheliaLabel,
    DomainLabel,
    DomainAddTraefikLabel,
    DomainRegexLabel,
    MethodsLabel,
    PolicyLabel,
    RankLabel,
    ResourcesLabel,
    SubjectLabel,
    TraefikRouterLabel,
]


def resolve(
    raw_labels: list[RawRuleLabel],
    other_labels: list[ParsedLabel],
) -> list[ResolvedRuleLabel]:
    return [
        resolved_label
        for label in raw_labels
        if (resolved_label := label.resolve(other_labels)) is not None
    ]
