from hypothesis import given

from dl2ac import config, models
from tests import shared


@given(shared.is_authelia_strategy)
def test_is_authelia_label(is_authelia: bool) -> None:
    label_key = config.IS_AUTHELIA_KEY
    label_value = str(is_authelia).lower()
    label = models.IsAutheliaLabel.try_parse(label_key, label_value)
    assert (label is not None) == is_authelia


@given(
    shared.rule_name_strategy,
    shared.index_strategy,
    shared.method_value_strategy,
)
def test_method_label(
    rule_name: str, index: int, method: models.AutheliaMethod
) -> None:
    label_key = config.METHODS_KEY_FORMAT.format(rule_name=rule_name, index=index)
    label_value = method.value
    label = models.MethodLabel.try_parse(label_key, label_value)
    assert label is not None
    assert label.rule_name == rule_name
    assert label.index == index
    assert label.method == method


@given(
    shared.rule_name_strategy,
    shared.policy_strategy,
)
def test_policy_label(rule_name: str, policy: config.AutheliaPolicy) -> None:
    label_key = config.POLICY_KEY_FORMAT.format(rule_name=rule_name)
    label_value = policy.value
    label = models.PolicyLabel.try_parse(label_key, label_value)
    assert label is not None
    assert label.rule_name == rule_name
    assert label.policy == policy


@given(shared.rule_name_strategy, shared.rank_strategy)
def test_rank_label(rule_name: str, rank: int) -> None:
    label_key = config.RANK_KEY_FORMAT.format(rule_name=rule_name)
    label_value = str(rank)
    label = models.RankLabel.try_parse(label_key, label_value)
    assert label is not None
    assert label.rule_name == rule_name
    assert label.rank == rank


@given(
    shared.rule_name_strategy,
    shared.index_strategy,
    shared.index_strategy,
    shared.subject_strategy,
)
def test_subject_label(
    rule_name: str,
    outer_index: int,
    inner_index: int,
    subject: str,
) -> None:
    label_key = config.SUBJECT_KEY_FORMAT.format(
        rule_name=rule_name, outer_index=outer_index, inner_index=inner_index
    )
    label_value = subject
    label = models.SubjectLabel.try_parse(label_key, label_value)
    assert label is not None
    assert label.rule_name == rule_name
    assert label.outer_index == outer_index
    assert label.inner_index == inner_index
    assert label.subject == subject
