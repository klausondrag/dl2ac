from hypothesis import given

from dl2ac import config, labels
from tests import shared


@given(shared.parsable_label_strategy)
def test_roundtrip_parsable_labels(expected_label: labels.ParsedLabel) -> None:
    actual_label = expected_label.try_parse(*expected_label.to_parsable_strings())
    assert actual_label == expected_label


@given(shared.parsable_label_strategy)
def test_only_one_parsable_label_matches(expected_label: labels.ParsedLabel) -> None:
    label_key, label_value = expected_label.to_parsable_strings()
    for label_class in labels.supported_parsable_label_types:
        if label_class == type(expected_label):
            continue

        actual_label = label_class.try_parse(label_key, label_value)
        assert actual_label is None


@given(shared.domain_from_traefik_label_strategy, shared.traefik_router_name_strategy)
def test_domain_from_traefik_label(
    expected_label: labels.DomainFromTraefikLabel, traefik_router_name: str
) -> None:
    traefik_router_label = labels.TraefikRouterLabel.try_parse(
        label_key=config.TRAEFIK_ROUTER_KEY_FORMAT.format(
            router_name=traefik_router_name,
        ),
        label_value=config.TRAEFIK_ROUTER_VALUE_FORMAT.format(
            domain=expected_label.domain,
        ),
    )
    assert traefik_router_label is not None

    domain_add_traefik_label = labels.DomainAddTraefikLabel.try_parse(
        label_key=config.DOMAIN_ADD_TRAEFIK_KEY_FORMAT.format(
            rule_name=expected_label.rule_name,
            index=expected_label.index,
        ),
        label_value=traefik_router_name,
    )
    assert domain_add_traefik_label is not None

    actual_label: labels.DomainFromTraefikLabel | None = (
        domain_add_traefik_label.resolve([traefik_router_label])
    )
    assert actual_label == expected_label
