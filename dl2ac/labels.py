import abc
import dataclasses
import enum
from typing import Generic, Self, TypeVar

from loguru import logger

from dl2ac import config


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

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.is-authelia': true
        if label_key != config.IS_AUTHELIA_KEY:
            return None

        is_authelia = label_value.lower() == config.IS_AUTHELIA_VALUE

        # TODO: add debug logging
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

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.methods.1': 'OPTIONS'
        if not (match := config.METHODS_KEY_REGEX.match(label_key)):
            return None

        # TODO: add option to use csv
        # TODO: add debug logging
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

    def to_data(self) -> tuple[int, AutheliaMethod]:
        return self.index, self.method


@dataclasses.dataclass
class PolicyLabel(RuleLabel[config.AutheliaPolicy]):
    policy: config.AutheliaPolicy

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.policy': 'one_factor'
        if not (match := config.POLICY_KEY_REGEX.match(label_key)):
            return None

        # TODO: add debug logging
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

    def to_data(self) -> config.AutheliaPolicy:
        return self.policy


@dataclasses.dataclass
class RankLabel(RuleLabel[int]):
    rank: int

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.rank': '20'
        if not (match := config.RANK_KEY_REGEX.match(label_key)):
            return None

        # TODO: add debug logging
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

    def to_data(self) -> int:
        return self.rank


@dataclasses.dataclass
class ResourcesLabel(RuleLabel[tuple[int, str]]):
    index: int
    resource: str

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.resources.1': '^/api([/?].*)?$'
        if not (match := config.RESOURCES_KEY_REGEX.match(label_key)):
            return None

        # TODO: add option to use csv
        # TODO: add debug logging
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

        resource = label_value

        return cls(rule_name=rule_name, index=index, resource=resource)

    def to_data(self) -> tuple[int, str]:
        return self.index, self.resource


@dataclasses.dataclass
class SubjectLabel(RuleLabel[tuple[int, int, str]]):
    outer_index: int
    inner_index: int
    subject: str

    @classmethod
    def try_parse(cls, label_key: str, label_value: str) -> Self | None:
        # 'dl2ac.rules.one.subjects.1.1': 'user:john'
        if not (match := config.SUBJECT_KEY_REGEX.match(label_key)):
            return None

        # TODO: add option to use csv
        # TODO: add debug logging
        # TODO: add validation for `user:`, `group:` and `oauth2:client:`
        rule_name = match.group(1)
        outer_index_str = match.group(2)
        inner_index_str = match.group(3)

        try:
            outer_index = int(outer_index_str)
        except ValueError:
            # TODO: add container id, container name, and label_key
            logger.warning(
                f'Invalid outer index value found, cannot parse `{outer_index_str}` as int.'
            )
            return None

        try:
            inner_index = int(inner_index_str)
        except ValueError:
            # TODO: add container id, container name, and label_key
            logger.warning(
                f'Invalid inner index value found, cannot parse `{inner_index_str}` as int.'
            )
            return None

        subject = label_value

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
