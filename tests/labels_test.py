from hypothesis import given, strategies as st

from dl2ac import config, models
from tests import shared


@given(st.booleans())
def test_is_authelia_label(is_authelia: bool) -> None:
    label_key = config.IS_AUTHELIA_KEY
    label_value = str(is_authelia).lower()
    label = models.IsAutheliaLabel.try_parse(label_key, label_value)
    assert (label is not None) == is_authelia


@given(
    shared.rule_name_strategy,
    st.sampled_from(config.AutheliaPolicy),
)
def test_policy_label(rule_name: str, policy: config.AutheliaPolicy) -> None:
    print(policy)
    label_key = config.POLICY_KEY_FORMAT.format(rule_name=rule_name)
    label_value = policy.value
    label = models.PolicyLabel.try_parse(label_key, label_value)
    assert label is not None
    assert label.rule_name == rule_name
    assert label.policy == policy


@given(shared.rule_name_strategy, st.integers())
def test_priority_label(rule_name: str, priority: int) -> None:
    label_key = config.PRIORITY_KEY_FORMAT.format(rule_name=rule_name)
    label_value = str(priority)
    label = models.PriorityLabel.try_parse(label_key, label_value)
    assert label is not None
    assert label.rule_name == rule_name
    assert label.priority == priority
