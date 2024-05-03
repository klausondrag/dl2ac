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


class LabelBase(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        pass


@dataclasses.dataclass
class IsAutheliaLabel(LabelBase):
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


LabelDataType = TypeVar('LabelDataType')


@dataclasses.dataclass
class RuleLabel(LabelBase, Generic[LabelDataType], abc.ABC):
    rule_name: str

    @abc.abstractmethod
    def to_data(self) -> LabelDataType:
        pass


@dataclasses.dataclass
class MethodLabel(RuleLabel[tuple[int, AutheliaMethod]]):
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

    def to_data(self) -> tuple[int, AutheliaMethod]:
        return self.index, self.method


@dataclasses.dataclass
class PolicyLabel(RuleLabel[config.AutheliaPolicy]):
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

    def to_data(self) -> config.AutheliaPolicy:
        return self.policy


@dataclasses.dataclass
class RankLabel(RuleLabel[int]):
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

    def to_data(self) -> int:
        return self.rank


@dataclasses.dataclass
class ResourcesLabel(RuleLabel[tuple[int, str]]):
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

    def to_data(self) -> tuple[int, str]:
        return self.index, self.resource


@dataclasses.dataclass
class SubjectLabel(RuleLabel[tuple[int, int, str]]):
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

    def to_data(self) -> tuple[int, int, str]:
        return self.outer_index, self.inner_index, self.subject


supported_label_types = [
    IsAutheliaLabel,
    MethodLabel,
    PolicyLabel,
    RankLabel,
    ResourcesLabel,
    SubjectLabel,
]
