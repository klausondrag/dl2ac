from hypothesis import given

from dl2ac import config, labels
from tests import shared


@given(shared.is_authelia_label_strategy)
def test_is_authelia_label(expected_label: labels.IsAutheliaLabel) -> None:
    actual_label = labels.IsAutheliaLabel.try_parse(
        label_key=config.IS_AUTHELIA_KEY,
        label_value=str(expected_label.is_authelia),
    )
    assert actual_label == expected_label


@given(shared.methods_label_strategy)
def test_methods_label(expected_label: labels.MethodsLabel) -> None:
    actual_label = labels.MethodsLabel.try_parse(
        label_key=config.METHODS_KEY_FORMAT.format(
            rule_name=expected_label.rule_name,
            index=expected_label.index,
        ),
        label_value=expected_label.method.value,
    )
    assert actual_label == expected_label


@given(shared.policy_label_strategy)
def test_policy_label(expected_label: labels.PolicyLabel) -> None:
    actual_label = labels.PolicyLabel.try_parse(
        label_key=config.POLICY_KEY_FORMAT.format(rule_name=expected_label.rule_name),
        label_value=expected_label.policy.value,
    )
    assert actual_label == expected_label


@given(shared.rank_label_strategy)
def test_rank_label(expected_label: labels.RankLabel) -> None:
    actual_label = labels.RankLabel.try_parse(
        label_key=config.RANK_KEY_FORMAT.format(rule_name=expected_label.rule_name),
        label_value=str(expected_label.rank),
    )
    assert actual_label == expected_label


@given(shared.resources_label_strategy)
def test_resources_label(expected_label: labels.ResourcesLabel) -> None:
    actual_label = labels.ResourcesLabel.try_parse(
        label_key=config.RESOURCES_KEY_FORMAT.format(
            rule_name=expected_label.rule_name,
            index=expected_label.index,
        ),
        label_value=expected_label.resource,
    )
    assert actual_label == expected_label


@given(shared.subject_label_strategy)
def test_subject_label(expected_label: labels.SubjectLabel) -> None:
    actual_label = labels.SubjectLabel.try_parse(
        label_key=config.SUBJECT_KEY_FORMAT.format(
            rule_name=expected_label.rule_name,
            outer_index=expected_label.outer_index,
            inner_index=expected_label.inner_index,
        ),
        label_value=expected_label.subject,
    )
    assert actual_label == expected_label
