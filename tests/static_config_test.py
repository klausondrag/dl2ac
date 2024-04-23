import re

from hypothesis import given

from dl2ac import config
from tests import shared


@given(shared.rule_name_strategy)
def test_policy_rule(expected_rule_name: str) -> None:
    _test_rule(config.POLICY_KEY_REGEX, config.POLICY_KEY_FORMAT, expected_rule_name)


@given(shared.rule_name_strategy)
def test_priority_rule(expected_rule_name: str) -> None:
    _test_rule(
        config.PRIORITY_KEY_REGEX, config.PRIORITY_KEY_FORMAT, expected_rule_name
    )


def _test_rule(regex: re.Pattern, format_string: str, expected_rule_name: str) -> None:
    formatted_string = format_string.format(rule_name=expected_rule_name)
    if match := regex.match(formatted_string):
        actual_rule_name = match.group(1)
        assert actual_rule_name == expected_rule_name
        return

    assert False
