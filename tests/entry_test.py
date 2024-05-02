import dataclasses
from typing import cast
from unittest.mock import Mock

from hypothesis import given, strategies as st

from dl2ac import config, entry, models
from tests import shared


parsed_container_strategy = st.builds(
    models.ParsedContainer,
    docker_container=st.none(),
    name=shared.container_name_strategy,
    is_authelia=shared.is_authelia_strategy,
    labels=st.lists(st.nothing()),
)

# Rules get sorted by first their rank, and second by their name.
# So, rule names should be unique to assure stable sorting.
sorted_rule_strategy = st.builds(
    models.SortedRule,
    name=shared.rule_name_strategy,
    methods=st.lists(shared.method_value_strategy),
    policy=shared.policy_strategy,
    subject=st.lists(
        st.one_of(
            shared.subject_strategy, st.lists(shared.subject_strategy, min_size=2)
        )
    ),
)

access_control_strategy = st.builds(
    models.AccessControl,
    default_policy=shared.policy_strategy,
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
    access_control: models.AccessControl = draw(access_control_strategy)
    n_sorted_rules = len(access_control.rules)
    default_rule_policy: config.AutheliaPolicy = draw(shared.policy_strategy)

    ranks = create_order_indices(draw, shared.rank_strategy, n_sorted_rules)
    labels: list[models.RuleLabel] = []
    label_strings: list[tuple[str, str]] = []
    for rank, sorted_rule in zip(ranks, access_control.rules):
        add_methods_label(draw, labels, label_strings, sorted_rule)
        add_policy_label(draw, labels, label_strings, sorted_rule, default_rule_policy)
        add_rank_label(labels, label_strings, sorted_rule, rank)
        add_subjects_label(draw, labels, label_strings, sorted_rule)

    parsed_containers: list[models.ParsedContainer] = draw(
        st.lists(parsed_container_strategy, min_size=1)
    )
    container_indices = distribute_labels(draw, labels, parsed_containers)
    docker_containers = create_docker_containers(parsed_containers)
    add_rule_labels(container_indices, docker_containers, label_strings)
    add_is_authelia_labels(draw, docker_containers, parsed_containers)
    docker_containers, parsed_containers = remove_containers_without_labels(
        docker_containers, parsed_containers
    )
    assign_docker_containers(docker_containers, parsed_containers)

    return docker_containers, parsed_containers, default_rule_policy, access_control


def create_order_indices(
    draw: st.DrawFn, strategy: st.SearchStrategy, size: int
) -> list[int]:
    indices = sorted(
        draw(
            st.lists(
                strategy,
                min_size=size,
                max_size=size,
                unique=True,
            )
        )
    )

    return indices


def add_methods_label(
    draw: st.DrawFn,
    labels: list[models.RuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: models.SortedRule,
) -> None:
    n_methods = len(sorted_rule.methods)
    methods_indices = create_order_indices(draw, shared.index_strategy, n_methods)
    for index, method in zip(methods_indices, sorted_rule.methods):
        method_label = models.MethodLabel(
            rule_name=sorted_rule.name, index=index, method=method
        )
        labels.append(method_label)

        method_label_string_key = config.METHODS_KEY_FORMAT.format(
            rule_name=sorted_rule.name,
            index=index,
        )
        method_label_string_value = method.value
        label_strings.append((method_label_string_key, method_label_string_value))


def add_policy_label(
    draw: st.DrawFn,
    labels: list[models.RuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: models.SortedRule,
    default_rule_policy: config.AutheliaPolicy,
) -> None:
    # If sorted_rule.policy == default_rule_policy
    # we randomly skip adding the label
    if sorted_rule.policy == default_rule_policy and draw(st.booleans()):
        return

    policy_label = models.PolicyLabel(
        rule_name=sorted_rule.name, policy=sorted_rule.policy
    )
    labels.append(policy_label)

    policy_label_string_key = config.POLICY_KEY_FORMAT.format(
        rule_name=sorted_rule.name
    )
    policy_label_string_value = sorted_rule.policy.value
    label_strings.append((policy_label_string_key, policy_label_string_value))


def add_rank_label(
    labels: list[models.RuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: models.SortedRule,
    rank: int,
) -> None:
    rank_label = models.RankLabel(rule_name=sorted_rule.name, rank=rank)
    labels.append(rank_label)

    rank_label_string_key = config.RANK_KEY_FORMAT.format(rule_name=sorted_rule.name)
    rank_label_string_value = str(rank)
    label_strings.append((rank_label_string_key, rank_label_string_value))


def add_subjects_label(
    draw: st.DrawFn,
    labels: list[models.RuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: models.SortedRule,
) -> None:
    n_outer_subjects = len(sorted_rule.subject)
    subject_outer_indices = create_order_indices(
        draw, shared.index_strategy, n_outer_subjects
    )
    for outer_index, inner_list in zip(subject_outer_indices, sorted_rule.subject):
        if isinstance(inner_list, str):
            # Add directly
            subject_label = models.SubjectLabel(
                rule_name=sorted_rule.name,
                outer_index=outer_index,
                inner_index=1,
                subject=inner_list,
            )
            labels.append(subject_label)

            subject_label_string_key = config.SUBJECT_KEY_FORMAT.format(
                rule_name=sorted_rule.name,
                outer_index=outer_index,
                inner_index=1,
            )
            subject_label_string_value = inner_list
            label_strings.append((subject_label_string_key, subject_label_string_value))
            continue

        n_inner_subjects = len(inner_list)
        subject_inner_indices = create_order_indices(
            draw, shared.index_strategy, n_inner_subjects
        )
        for inner_index, subject in zip(subject_inner_indices, inner_list):
            subject_label = models.SubjectLabel(
                rule_name=sorted_rule.name,
                outer_index=outer_index,
                inner_index=inner_index,
                subject=subject,
            )
            labels.append(subject_label)

            subject_label_string_key = config.SUBJECT_KEY_FORMAT.format(
                rule_name=sorted_rule.name,
                outer_index=outer_index,
                inner_index=inner_index,
            )
            subject_label_string_value = subject
            label_strings.append((subject_label_string_key, subject_label_string_value))


def distribute_labels(
    draw: st.DrawFn,
    labels: list[models.RuleLabel],
    parsed_containers: list[models.ParsedContainer],
) -> list[int]:
    n_labels = len(labels)
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

    return container_indices


def create_docker_containers(
    parsed_containers: list[models.ParsedContainer],
) -> list[FakeDockerContainer]:
    docker_containers = [
        FakeDockerContainer(
            name=parsed_container.name,
            labels={},
        )
        for parsed_container in parsed_containers
    ]

    return docker_containers


def add_rule_labels(
    container_indices: list[int],
    docker_containers: list[FakeDockerContainer],
    label_strings: list[tuple[str, str]],
):
    for container_index, (label_key, label_value) in zip(
        container_indices, label_strings
    ):
        docker_containers[container_index].labels[label_key] = label_value


def add_is_authelia_labels(
    draw: st.DrawFn,
    docker_containers: list[FakeDockerContainer],
    parsed_containers: list[models.ParsedContainer],
) -> None:
    for docker_container, parsed_container in zip(docker_containers, parsed_containers):
        label_key = config.IS_AUTHELIA_KEY
        if parsed_container.is_authelia:
            # If a container is authelia
            # then an IsAutheliaLabel is mandatory
            label_value = str(True).lower()
        else:
            # If a container is not authelia
            # then an IsAutheliaLabel is optional
            if draw(shared.is_authelia_strategy):
                label_value = str(False).lower()
            else:
                continue

        docker_container.labels[label_key] = label_value


def remove_containers_without_labels(
    docker_containers: list[FakeDockerContainer],
    parsed_containers: list[models.ParsedContainer],
) -> tuple[list[FakeDockerContainer], list[models.ParsedContainer]]:
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

    return docker_containers, parsed_containers


def assign_docker_containers(
    docker_containers: list[FakeDockerContainer],
    parsed_containers: list[models.ParsedContainer],
) -> None:
    for docker_container, parsed_container in zip(docker_containers, parsed_containers):
        parsed_container.docker_container = cast(
            models.DockerContainer, docker_container
        )


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


# TODO: test invalid data
