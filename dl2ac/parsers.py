import abc
import dataclasses
import enum
import re
from typing import Generic, TypeVar

from loguru import logger


ParserOutputType = TypeVar('ParserOutputType')


class Parser(Generic[ParserOutputType], abc.ABC):
    @abc.abstractmethod
    def from_str(self, value: str) -> ParserOutputType | None:
        pass


# We re-define the type here instead of using the one from config.py.
# The argument to Generic[...] cannot be a dotted name.
# So, config.EnumType is invalid, but EnumType is valid.
EnumType = TypeVar('EnumType', bound=enum.Enum)


@dataclasses.dataclass
class BoolParser(Parser[bool]):
    field_name: str

    def from_str(self, value: str) -> bool | None:
        try:
            # bool(value) would be wrong
            # bool('False') == True
            return value.lower() == 'true'
        except ValueError:
            # TODO: add container id, container name, and label_key
            logger.warning(
                f'Invalid {self.field_name} value found, cannot parse `{value}` as boolean.'
            )
            return None


@dataclasses.dataclass
class EnumParser(Parser[EnumType]):
    field_name: str
    enum_type: type[EnumType]
    enum_name: str
    allowed_values: str

    def from_str(self, value: str) -> EnumType | None:
        try:
            return self.enum_type[value.upper()]
        except KeyError:
            # TODO: add container id, container name, and label_key
            logger.warning(
                f'Invalid {self.field_name} value found, cannot parse `{value}` as a {self.enum_name}.'
                f' Must be one of [{self.allowed_values}].'
            )
            return None


@dataclasses.dataclass
class IntParser(Parser[int]):
    field_name: str

    def from_str(self, value: str) -> int | None:
        try:
            return int(value)
        except ValueError:
            # TODO: add container id, container name, and label_key
            logger.warning(
                f'Invalid {self.field_name} value found, cannot parse `{value}` as int.'
            )
            return None


class StringParser(Parser[str]):
    def from_str(self, value: str) -> str | None:
        return value


@dataclasses.dataclass
class RuleStringParser(Parser[bool]):
    rule_string: str

    def from_str(self, value: str) -> bool | None:
        # We could also just return a bool
        # but we want to keep the pattern of returning data_type | None.
        # In this case, ParserOutputType only has one value though.

        # 'dl2ac.is-authelia': true
        if value != self.rule_string:
            return None

        return True


@dataclasses.dataclass
class RuleRegexParser(Parser[str]):
    regex: re.Pattern

    def from_str(self, value: str) -> str | None:
        # 'dl2ac.rules.one.policy': 'one_factor'
        if not (match := self.regex.match(value)):
            return None

        rule_name = match.group(1)
        return rule_name


@dataclasses.dataclass
class RuleWithOneIndexRegexParser(Parser[tuple[str, int]]):
    regex: re.Pattern
    index_parser = IntParser('index')

    def from_str(self, value: str) -> tuple[str, int] | None:
        # 'dl2ac.rules.one.methods.1': 'OPTIONS'
        if not (match := self.regex.match(value)):
            return None

        rule_name = match.group(1)
        index = self.index_parser.from_str(match.group(2))
        if index is None:
            return None

        return rule_name, index


@dataclasses.dataclass
class RuleWithTwoIndicesRegexParser(Parser[tuple[str, int, int]]):
    regex: re.Pattern
    index_parser = IntParser('index')

    def from_str(self, value: str) -> tuple[str, int, int] | None:
        # 'dl2ac.rules.one.subjects.1.1': 'user:john'
        if not (match := self.regex.match(value)):
            return None

        rule_name = match.group(1)
        outer_index = self.index_parser.from_str(match.group(2))
        if outer_index is None:
            return None

        inner_index = self.index_parser.from_str(match.group(3))
        if inner_index is None:
            return None

        return rule_name, outer_index, inner_index
