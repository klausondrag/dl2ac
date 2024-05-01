import dataclasses
from typing import cast
from unittest.mock import Mock

from hypothesis import given, strategies as st

from dl2ac import config, entry, models
from tests import shared


parsed_container_strategy = st.builds(
    models.ParsedContainer,
    docker_container=st.none(),
    name=st.text(),
    is_authelia=st.booleans(),
    labels=st.lists(st.nothing()),
)

# Rules get sorted by first their rank, and second by their name.
# So, rule names should be unique to assure stable sorting.
sorted_rule_strategy = st.builds(
    models.SortedRule,
    name=shared.rule_name_strategy,
    policy=st.sampled_from(config.AutheliaPolicy),
)

access_control_strategy = st.builds(
    models.AccessControl,
    default_policy=st.sampled_from(config.AutheliaPolicy),
    rules=st.lists(sorted_rule_strategy, unique_by=lambda r: r.name),
)


@dataclasses.dataclass
class FakeDockerContainer:
    name: str
    labels: dict[str, str]


@st.composite
def containers_and_access_control(
    draw: st.DrawFn,
) -> tuple[
    list[FakeDockerContainer],
    list[models.ParsedContainer],
    config.AutheliaPolicy,
    models.AccessControl,
]:
    access_control = draw(access_control_strategy)
    n_sorted_rules = len(access_control.rules)
    default_rule_policy = draw(shared.policy_strategy)

    ranks = sorted(
        draw(
            st.lists(
                st.integers(),
                min_size=n_sorted_rules,
                max_size=n_sorted_rules,
                unique=True,
            )
        )
    )
    labels: list[models.RuleLabel] = []
    label_strings: list[tuple[str, str]] = []
    for sorted_rule, rank in zip(access_control.rules, ranks):
        if sorted_rule.policy != default_rule_policy or draw(st.booleans()):
            # If sorted_rule.policy == default_rule_policy
            # we randomly skip adding the label
            policy_label = models.PolicyLabel(
                rule_name=sorted_rule.name, policy=sorted_rule.policy
            )
            labels.append(policy_label)

            policy_label_string_key = config.POLICY_KEY_FORMAT.format(
                rule_name=sorted_rule.name
            )
            policy_label_string_value = sorted_rule.policy.value
            label_strings.append((policy_label_string_key, policy_label_string_value))

        rank_label = models.RankLabel(rule_name=sorted_rule.name, rank=rank)
        labels.append(rank_label)

        rank_label_string_key = config.RANK_KEY_FORMAT.format(
            rule_name=sorted_rule.name
        )
        rank_label_string_value = str(rank)
        label_strings.append((rank_label_string_key, rank_label_string_value))

    n_labels = len(labels)
    parsed_containers: list[models.ParsedContainer] = draw(
        st.lists(parsed_container_strategy, min_size=1)
    )
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

    docker_containers = [
        FakeDockerContainer(
            name=parsed_container.name,
            labels={},
        )
        for parsed_container in parsed_containers
    ]
    for container_index, (label_key, label_value) in zip(
        container_indices, label_strings
    ):
        docker_containers[container_index].labels[label_key] = label_value

    for docker_container, parsed_container in zip(docker_containers, parsed_containers):
        label_key = config.IS_AUTHELIA_KEY
        if parsed_container.is_authelia:
            # If a container is authelia
            # then an IsAutheliaLabel is mandatory
            label_value = str(True).lower()
        else:
            # If a container is not authelia
            # then an IsAutheliaLabel is optional
            if draw(st.booleans()):
                label_value = str(False).lower()
            else:
                continue

        docker_container.labels[label_key] = label_value

    container_indices_to_remove = {
        index
        for index, parsed_container in enumerate(parsed_containers)
        if len(parsed_container.labels) == 0
    }

    docker_containers = [
        docker_container
        for index, docker_container in enumerate(docker_containers)
        if index not in container_indices_to_remove
    ]

    parsed_containers = [
        parsed_container
        for index, parsed_container in enumerate(parsed_containers)
        if index not in container_indices_to_remove
    ]

    for docker_container, parsed_container in zip(docker_containers, parsed_containers):
        parsed_container.docker_container = cast(
            models.DockerContainer, docker_container
        )

    return docker_containers, parsed_containers, default_rule_policy, access_control


@given(containers_and_access_control())
def test_valid_load_containers(
    data: tuple[
        list[FakeDockerContainer],
        list[models.ParsedContainer],
        config.AutheliaPolicy,
        models.AccessControl,
    ],
):
    docker_containers: list[FakeDockerContainer]
    expected_parsed_containers: list[models.ParsedContainer]
    docker_containers, expected_parsed_containers, _, _ = data

    fake_client = Mock()
    fake_client.containers.list.return_value = docker_containers
    actual_parsed_containers = entry.load_containers(fake_client)

    assert actual_parsed_containers == expected_parsed_containers


@given(containers_and_access_control())
def test_valid_to_authelia_data(
    data: tuple[
        list[FakeDockerContainer],
        list[models.ParsedContainer],
        config.AutheliaPolicy,
        models.AccessControl,
    ],
) -> None:
    parsed_containers: list[models.ParsedContainer]
    expected_access_control: models.AccessControl
    _, parsed_containers, default_rule_policy, expected_access_control = data

    actual_access_control_dict = entry.to_authelia_data(
        parsed_containers=parsed_containers,
        default_authelia_policy=expected_access_control.default_policy,
        default_rule_policy=default_rule_policy,
    )

    expected_access_control_dict = dataclasses.asdict(
        expected_access_control, dict_factory=models.enum_as_value_factory
    )

    assert actual_access_control_dict == expected_access_control_dict
