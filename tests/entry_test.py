import dataclasses

from hypothesis import given, strategies as st
from loguru import logger

from dl2ac import config, entry, models
from tests import shared


parsed_container_strategy = st.builds(
    models.ParsedContainer,
    docker_container=st.none(),
    name=st.text(),
    is_authelia=st.booleans(),
    labels=st.lists(st.nothing()),
)

sorted_rule_strategy = st.builds(
    models.SortedRule,
    name=st.text(min_size=1),
    policy=st.sampled_from(config.AutheliaPolicy),
)

access_control_strategy = st.builds(
    models.AccessControl,
    default_policy=st.sampled_from(config.AutheliaPolicy),
    rules=st.lists(sorted_rule_strategy, unique_by=lambda r: r.name),
)


@st.composite
def containers_and_access_control(
    draw: st.DrawFn,
) -> tuple[list[models.ParsedContainer], models.AccessControl, config.AutheliaPolicy]:
    access_control = draw(access_control_strategy)
    n_sorted_rules = len(access_control.rules)
    default_rule_policy = draw(shared.policy_strategy)

    priorities = sorted(
        draw(
            st.lists(
                st.integers(),
                min_size=n_sorted_rules,
                max_size=n_sorted_rules,
                unique=True,
            )
        )
    )
    labels = []
    for sorted_rule, priority in zip(access_control.rules, priorities):
        if sorted_rule.policy != default_rule_policy or draw(st.booleans()):
            # If sorted_rule.policy == default_rule_policy
            # we randomly skip adding the label
            policy_label = models.PolicyLabel(
                rule_name=sorted_rule.name, policy=sorted_rule.policy
            )
            labels.append(policy_label)

        priority_label = models.PriorityLabel(
            rule_name=sorted_rule.name, priority=priority
        )
        labels.append(priority_label)

    n_labels = len(labels)
    parsed_containers = draw(st.lists(parsed_container_strategy, min_size=1))
    n_containers = len(parsed_containers)
    container_indices = draw(
        st.lists(
            st.integers(min_value=0, max_value=n_containers - 1),
            min_size=n_labels,
            max_size=n_labels,
        )
    )
    for container_index, label in zip(container_indices, labels):
        parsed_containers[container_index].labels.append(label)

    return parsed_containers, access_control, default_rule_policy


@given(containers_and_access_control())
def test_to_authelia_data(
    data: tuple[
        list[models.ParsedContainer], models.AccessControl, config.AutheliaPolicy
    ],
) -> None:
    parsed_containers: list[models.ParsedContainer]
    expected_access_control: models.AccessControl
    parsed_containers, expected_access_control, default_rule_policy = data
    logger.debug(f'{parsed_containers=}')
    logger.debug(f'{expected_access_control=}')

    actual_access_control_dict = entry.to_authelia_data(
        parsed_containers=parsed_containers,
        default_authelia_policy=expected_access_control.default_policy,
        default_rule_policy=default_rule_policy,
    )
    logger.debug(f'{actual_access_control_dict=}')

    expected_access_control_dict = dataclasses.asdict(
        expected_access_control, dict_factory=models.enum_as_value_factory
    )
    logger.debug(f'{expected_access_control_dict=}')

    assert actual_access_control_dict == expected_access_control_dict
