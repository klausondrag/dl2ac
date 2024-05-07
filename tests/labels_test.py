from hypothesis import given
from loguru import logger

from dl2ac import config, labels
from tests import shared


@given(shared.parsable_label_strategy)
def test_roundtrip_parsable_labels(expected_label: labels.ParsedLabel) -> None:
    actual_label = expected_label.try_parse(*expected_label.to_parsable_strings())
    assert actual_label == expected_label


@given(shared.parsable_label_strategy)
def test_only_one_parsable_label_matches(expected_label: labels.ParsedLabel) -> None:
    label_key, label_value = expected_label.to_parsable_strings()
    for label_class in labels.ParsedLabel.registered_parsable_label_types:
        if label_class == type(expected_label):
            continue

        actual_label = label_class.try_parse(label_key, label_value)
        assert actual_label is None


@given(shared.domain_from_traefik_label_strategy, shared.traefik_router_name_strategy)
def test_domain_from_traefik_label(
    expected_label: labels.DomainFromTraefikLabel, traefik_router_name: str
) -> None:
    raw_rule_labels: list[labels.RawRuleLabel] = []
    other_labels: list[labels.ParsedLabel] = []

    traefik_router_label = labels.TraefikRouterLabel.try_parse(
        label_key=config.TRAEFIK_ROUTER_KEY_FORMAT.format(
            router_name=traefik_router_name,
        ),
        label_value=config.TRAEFIK_ROUTER_VALUE_FORMAT.format(
            domain=expected_label.domain,
        ),
    )
    assert traefik_router_label is not None
    other_labels.append(traefik_router_label)

    domain_add_traefik_label = labels.DomainAddTraefikLabel.try_parse(
        label_key=config.DOMAIN_ADD_TRAEFIK_KEY_FORMAT.format(
            rule_name=expected_label.rule_name,
            index=expected_label.index,
        ),
        label_value=traefik_router_name,
    )
    assert domain_add_traefik_label is not None
    raw_rule_labels.append(domain_add_traefik_label)

    actual_label: labels.DomainFromTraefikLabel | None = (
        domain_add_traefik_label.resolve(
            raw_rule_labels=raw_rule_labels, other_labels=other_labels
        )
    )
    assert actual_label == expected_label


@given(shared.query_label_strategy)
def test_query_label(expected_label: labels.QueryLabel) -> None:
    logger.debug(f'{expected_label=}')
    raw_rule_labels: list[labels.RawRuleLabel] = []
    other_labels: list[labels.ParsedLabel] = []

    query_key_label = labels.QueryKeyLabel.try_parse(
        label_key=config.QUERY_KEY_KEY_FORMAT.format(
            rule_name=expected_label.rule_name,
            outer_index=expected_label.outer_index,
            inner_index=expected_label.inner_index,
        ),
        label_value=expected_label.query.key,
    )
    logger.debug(f'{query_key_label=}')
    assert query_key_label is not None
    raw_rule_labels.append(query_key_label)

    if expected_label.query.operator is not None:
        query_operator_label = labels.QueryOperatorLabel.try_parse(
            label_key=config.QUERY_OPERATOR_KEY_FORMAT.format(
                rule_name=expected_label.rule_name,
                outer_index=expected_label.outer_index,
                inner_index=expected_label.inner_index,
            ),
            label_value=expected_label.query.operator.value,
        )
        assert query_operator_label is not None
        logger.debug(f'{query_operator_label=}')
        raw_rule_labels.append(query_operator_label)

    if expected_label.query.value is not None:
        query_value_label = labels.QueryValueLabel.try_parse(
            label_key=config.QUERY_VALUE_KEY_FORMAT.format(
                rule_name=expected_label.rule_name,
                outer_index=expected_label.outer_index,
                inner_index=expected_label.inner_index,
            ),
            label_value=expected_label.query.value,
        )
        assert query_value_label is not None
        logger.debug(f'{query_value_label=}')
        raw_rule_labels.append(query_value_label)

    actual_label: labels.QueryLabel | None = query_key_label.resolve(
        raw_rule_labels=raw_rule_labels, other_labels=other_labels
    )
    logger.debug(f'{actual_label=}, {raw_rule_labels=}, {other_labels=}')
    assert actual_label == expected_label
