import dataclasses
from typing import cast
from unittest.mock import Mock

from hypothesis import given, strategies as st

from dl2ac import config, containers, entry, labels as dl2ac_labels, rules
from tests import shared


parsed_container_strategy = st.builds(
    containers.ParsedContainer,
    docker_container=st.none(),
    name=shared.container_name_strategy,
    is_authelia=shared.is_authelia_strategy,
    raw_rule_labels=st.lists(st.nothing()),
    other_labels=st.lists(st.nothing()),
)

# Rules get sorted by first their rank, and second by their name.
# So, rule names should be unique to assure stable sorting.
sorted_rule_strategy = st.builds(
    rules.SortedRule,
    name=shared.rule_name_strategy,
    domain=st.lists(shared.domain_strategy),
    domain_regex=st.lists(shared.domain_regex_strategy),
    methods=st.lists(shared.methods_strategy),
    policy=shared.policy_strategy,
    resources=st.lists(shared.resources_strategy),
    subject=st.lists(
        st.one_of(
            shared.subject_strategy, st.lists(shared.subject_strategy, min_size=2)
        )
    ),
)

access_control_strategy = st.builds(
    rules.AccessControl,
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
    list[containers.ParsedContainer],
    config.AutheliaPolicy,
    rules.AccessControl,
]:
    access_control: rules.AccessControl = draw(access_control_strategy)
    n_sorted_rules = len(access_control.rules)
    default_rule_policy: config.AutheliaPolicy = draw(shared.policy_strategy)

    n_simple_domain_labels_per_rule, traefik_router_names_per_rule = (
        get_traefik_router_names(draw, access_control.rules)
    )
    assert len(n_simple_domain_labels_per_rule) == len(traefik_router_names_per_rule)
    assert len(n_simple_domain_labels_per_rule) == len(access_control.rules)

    ranks = create_order_indices(draw, shared.rank_strategy, n_sorted_rules)
    parsed_labels: list[dl2ac_labels.ParsedLabel] = []
    parsed_label_strings: list[tuple[str, str]] = []
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel] = []
    raw_rule_label_strings: list[tuple[str, str]] = []
    for index, (
        rank,
        sorted_rule,
        n_simple_domain_labels,
        traefik_router_names,
    ) in enumerate(
        zip(
            ranks,
            access_control.rules,
            n_simple_domain_labels_per_rule,
            traefik_router_names_per_rule,
        )
    ):
        add_domain_label(
            draw,
            raw_rule_labels,
            raw_rule_label_strings,
            sorted_rule,
            n_simple_domain_labels,
            traefik_router_names,
            parsed_labels,
            parsed_label_strings,
        )
        add_domain_regex_label(
            draw, raw_rule_labels, raw_rule_label_strings, sorted_rule
        )
        add_methods_label(draw, raw_rule_labels, raw_rule_label_strings, sorted_rule)
        add_policy_label(
            draw,
            raw_rule_labels,
            raw_rule_label_strings,
            sorted_rule,
            default_rule_policy,
        )
        add_rank_label(raw_rule_labels, raw_rule_label_strings, sorted_rule, rank)
        add_resources_label(draw, raw_rule_labels, raw_rule_label_strings, sorted_rule)
        add_subject_label(draw, raw_rule_labels, raw_rule_label_strings, sorted_rule)

    parsed_containers: list[containers.ParsedContainer] = draw(
        st.lists(parsed_container_strategy, min_size=1)
    )
    docker_containers = create_docker_containers(parsed_containers)

    raw_rule_labels_container_indices = distribute_raw_rule_labels(
        draw, raw_rule_labels, parsed_containers
    )
    add_rule_labels(
        raw_rule_labels_container_indices, docker_containers, raw_rule_label_strings
    )

    parsed_labels_container_indices = distribute_parsed_labels(
        draw, parsed_labels, parsed_containers
    )
    add_rule_labels(
        parsed_labels_container_indices, docker_containers, parsed_label_strings
    )

    add_is_authelia_labels(draw, docker_containers, parsed_containers)
    docker_containers, parsed_containers = remove_containers_without_labels(
        docker_containers, parsed_containers
    )
    assign_docker_containers(docker_containers, parsed_containers)

    return docker_containers, parsed_containers, default_rule_policy, access_control


def get_traefik_router_names(
    draw: st.DrawFn, sorted_rules: list[rules.SortedRule]
) -> tuple[list[int], list[list[str]]]:
    # This method ensures that the traefik router names are unique.
    # Since we need multiple router names for each sorted rule,
    # we need to sample them once globally and then distribute them to each rule.
    n_traefik_router_names_per_rule: list[int] = []
    n_simple_domain_labels_per_rule: list[int] = []
    for sorted_rule in sorted_rules:
        n_domains = len(sorted_rule.domain)
        # Domains from traefik get appended to the ones from regular DomainLabels.
        # So, we split the domains into ones from DomainLabel and ones from DomainFromTraefik.
        n_simple_domain_labels: int = draw(
            st.integers(min_value=0, max_value=n_domains)
        )
        n_simple_domain_labels_per_rule.append(n_simple_domain_labels)

        n_traefik_router_names = n_domains - n_simple_domain_labels
        n_traefik_router_names_per_rule.append(n_traefik_router_names)

    n_traefik_router_names_total: int = sum(n_traefik_router_names_per_rule)
    traefik_router_names_total: list[str] = draw(
        st.lists(
            shared.traefik_router_name_strategy,
            min_size=n_traefik_router_names_total,
            max_size=n_traefik_router_names_total,
            unique=True,
        )
    )
    traefik_router_names_per_rule: list[list[str]] = []
    start_index = 0
    for n_router_names in n_traefik_router_names_per_rule:
        end_index = start_index + n_router_names
        router_names: list[str] = traefik_router_names_total[start_index:end_index]
        traefik_router_names_per_rule.append(router_names)
        start_index += n_router_names

    assert (
        sum(len(router_names) for router_names in traefik_router_names_per_rule)
        == n_traefik_router_names_total
    )
    assert [
        len(router_names) for router_names in traefik_router_names_per_rule
    ] == n_traefik_router_names_per_rule

    return n_simple_domain_labels_per_rule, traefik_router_names_per_rule


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


def add_domain_label(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: rules.SortedRule,
    n_simple_domain_labels: int,
    traefik_router_names: list[str],
    parsed_labels: list[dl2ac_labels.ParsedLabel],
    parsed_label_strings: list[tuple[str, str]],
) -> None:
    add_simple_domain_label(
        draw,
        raw_rule_labels,
        label_strings,
        sorted_rule.name,
        sorted_rule.domain[:n_simple_domain_labels],
    )
    add_domain_from_traefik_label(
        draw,
        raw_rule_labels,
        label_strings,
        sorted_rule.name,
        sorted_rule.domain[n_simple_domain_labels:],
        traefik_router_names,
        parsed_labels,
        parsed_label_strings,
    )


def add_simple_domain_label(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule_name: str,
    domains: list[str],
) -> None:
    n_domains = len(domains)
    domain_indices = create_order_indices(draw, shared.index_strategy, n_domains)
    for index, domain in zip(domain_indices, domains):
        domain_label = dl2ac_labels.DomainLabel(
            rule_name=sorted_rule_name, index=index, domain=domain
        )
        raw_rule_labels.append(domain_label)

        domain_label_string_key = config.DOMAIN_KEY_FORMAT.format(
            rule_name=sorted_rule_name,
            index=index,
        )
        domain_label_string_value = domain
        label_strings.append((domain_label_string_key, domain_label_string_value))


def add_domain_from_traefik_label(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule_name: str,
    domains: list[str],
    traefik_router_names: list[str],
    parsed_labels: list[dl2ac_labels.ParsedLabel],
    parsed_label_strings: list[tuple[str, str]],
) -> None:
    n_domains = len(domains)
    n_router_names = len(traefik_router_names)
    assert n_domains == n_router_names
    domain_indices = create_order_indices(draw, shared.index_strategy, n_domains)
    for index, domain, traefik_router_name in zip(
        domain_indices, domains, traefik_router_names
    ):
        traefik_router_label = dl2ac_labels.TraefikRouterLabel(
            traefik_router_name=traefik_router_name, domain=domain
        )
        parsed_labels.append(traefik_router_label)

        domain_add_traefik_label = dl2ac_labels.DomainAddTraefikLabel(
            rule_name=sorted_rule_name,
            index=index,
            traefik_router_name=traefik_router_name,
        )
        raw_rule_labels.append(domain_add_traefik_label)

        traefik_router_label_string_key = config.TRAEFIK_ROUTER_KEY_FORMAT.format(
            router_name=traefik_router_name,
        )
        traefik_router_label_string_value = config.TRAEFIK_ROUTER_VALUE_FORMAT.format(
            domain=domain,
        )
        parsed_label_strings.append(
            (traefik_router_label_string_key, traefik_router_label_string_value)
        )

        domain_add_traefik_label_string_key = (
            config.DOMAIN_ADD_TRAEFIK_KEY_FORMAT.format(
                rule_name=sorted_rule_name,
                index=index,
            )
        )
        domain_add_traefik_label_string_value = traefik_router_name
        label_strings.append(
            (domain_add_traefik_label_string_key, domain_add_traefik_label_string_value)
        )


def add_domain_regex_label(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: rules.SortedRule,
) -> None:
    n_domain_regexes = len(sorted_rule.domain_regex)
    domain_regex_indices = create_order_indices(
        draw, shared.index_strategy, n_domain_regexes
    )
    for index, domain_regex in zip(domain_regex_indices, sorted_rule.domain_regex):
        domain_regex_label = dl2ac_labels.DomainRegexLabel(
            rule_name=sorted_rule.name, index=index, domain_regex=domain_regex
        )
        raw_rule_labels.append(domain_regex_label)

        domain_regex_label_string_key = config.DOMAIN_REGEX_KEY_FORMAT.format(
            rule_name=sorted_rule.name,
            index=index,
        )
        domain_regex_label_string_value = domain_regex
        label_strings.append(
            (domain_regex_label_string_key, domain_regex_label_string_value)
        )


def add_methods_label(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: rules.SortedRule,
) -> None:
    n_methods = len(sorted_rule.methods)
    methods_indices = create_order_indices(draw, shared.index_strategy, n_methods)
    for index, method in zip(methods_indices, sorted_rule.methods):
        method_label = dl2ac_labels.MethodsLabel(
            rule_name=sorted_rule.name, index=index, method=method
        )
        raw_rule_labels.append(method_label)

        method_label_string_key = config.METHODS_KEY_FORMAT.format(
            rule_name=sorted_rule.name,
            index=index,
        )
        method_label_string_value = method.value
        label_strings.append((method_label_string_key, method_label_string_value))


def add_policy_label(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: rules.SortedRule,
    default_rule_policy: config.AutheliaPolicy,
) -> None:
    # If sorted_rule.policy == default_rule_policy
    # we randomly skip adding the label
    if sorted_rule.policy == default_rule_policy and draw(st.booleans()):
        return

    policy_label = dl2ac_labels.PolicyLabel(
        rule_name=sorted_rule.name, policy=sorted_rule.policy
    )
    raw_rule_labels.append(policy_label)

    policy_label_string_key = config.POLICY_KEY_FORMAT.format(
        rule_name=sorted_rule.name
    )
    policy_label_string_value = sorted_rule.policy.value
    label_strings.append((policy_label_string_key, policy_label_string_value))


def add_rank_label(
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: rules.SortedRule,
    rank: int,
) -> None:
    rank_label = dl2ac_labels.RankLabel(rule_name=sorted_rule.name, rank=rank)
    raw_rule_labels.append(rank_label)

    rank_label_string_key = config.RANK_KEY_FORMAT.format(rule_name=sorted_rule.name)
    rank_label_string_value = str(rank)
    label_strings.append((rank_label_string_key, rank_label_string_value))


def add_resources_label(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: rules.SortedRule,
) -> None:
    n_resources = len(sorted_rule.resources)
    resources_indices = create_order_indices(draw, shared.index_strategy, n_resources)
    for index, resource in zip(resources_indices, sorted_rule.resources):
        resource_label = dl2ac_labels.ResourcesLabel(
            rule_name=sorted_rule.name, index=index, resource=resource
        )
        raw_rule_labels.append(resource_label)

        resource_label_string_key = config.RESOURCES_KEY_FORMAT.format(
            rule_name=sorted_rule.name,
            index=index,
        )
        resource_label_string_value = resource
        label_strings.append((resource_label_string_key, resource_label_string_value))


def add_subject_label(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    label_strings: list[tuple[str, str]],
    sorted_rule: rules.SortedRule,
) -> None:
    n_outer_subjects = len(sorted_rule.subject)
    subject_outer_indices = create_order_indices(
        draw, shared.index_strategy, n_outer_subjects
    )
    for outer_index, inner_list in zip(subject_outer_indices, sorted_rule.subject):
        if isinstance(inner_list, str):
            # Add directly
            subject_label = dl2ac_labels.SubjectLabel(
                rule_name=sorted_rule.name,
                outer_index=outer_index,
                inner_index=1,
                subject=inner_list,
            )
            raw_rule_labels.append(subject_label)

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
            subject_label = dl2ac_labels.SubjectLabel(
                rule_name=sorted_rule.name,
                outer_index=outer_index,
                inner_index=inner_index,
                subject=subject,
            )
            raw_rule_labels.append(subject_label)

            subject_label_string_key = config.SUBJECT_KEY_FORMAT.format(
                rule_name=sorted_rule.name,
                outer_index=outer_index,
                inner_index=inner_index,
            )
            subject_label_string_value = subject
            label_strings.append((subject_label_string_key, subject_label_string_value))


def distribute_raw_rule_labels(
    draw: st.DrawFn,
    raw_rule_labels: list[dl2ac_labels.RawRuleLabel],
    parsed_containers: list[containers.ParsedContainer],
) -> list[int]:
    n_labels = len(raw_rule_labels)
    n_containers = len(parsed_containers)
    container_indices = draw(
        st.lists(
            st.integers(min_value=0, max_value=n_containers - 1),
            min_size=n_labels,
            max_size=n_labels,
        )
    )
    for container_index, label in zip(container_indices, raw_rule_labels):
        parsed_containers[container_index].raw_rule_labels.append(label)

    return container_indices


def distribute_parsed_labels(
    draw: st.DrawFn,
    parsed_labels: list[dl2ac_labels.ParsedLabel],
    parsed_containers: list[containers.ParsedContainer],
) -> list[int]:
    n_labels = len(parsed_labels)
    n_containers = len(parsed_containers)
    container_indices = draw(
        st.lists(
            st.integers(min_value=0, max_value=n_containers - 1),
            min_size=n_labels,
            max_size=n_labels,
        )
    )
    for container_index, label in zip(container_indices, parsed_labels):
        parsed_containers[container_index].other_labels.append(label)

    return container_indices


def create_docker_containers(
    parsed_containers: list[containers.ParsedContainer],
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
    parsed_containers: list[containers.ParsedContainer],
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
    parsed_containers: list[containers.ParsedContainer],
) -> tuple[list[FakeDockerContainer], list[containers.ParsedContainer]]:
    container_indices_to_remove = {
        index
        for index, parsed_container in enumerate(parsed_containers)
        if len(parsed_container.raw_rule_labels) == 0
        and len(parsed_container.other_labels) == 0
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
    parsed_containers: list[containers.ParsedContainer],
) -> None:
    for docker_container, parsed_container in zip(docker_containers, parsed_containers):
        parsed_container.docker_container = cast(
            containers.DockerContainer, docker_container
        )


@given(containers_and_access_control())
def test_valid_load_containers(
    data: tuple[
        list[FakeDockerContainer],
        list[containers.ParsedContainer],
        config.AutheliaPolicy,
        rules.AccessControl,
    ],
):
    docker_containers: list[FakeDockerContainer]
    expected_parsed_containers: list[containers.ParsedContainer]
    docker_containers, expected_parsed_containers, _, _ = data

    fake_client = Mock()
    fake_client.containers.list.return_value = docker_containers
    actual_parsed_containers = entry.load_containers(fake_client)

    assert actual_parsed_containers == expected_parsed_containers


@given(containers_and_access_control())
def test_valid_to_authelia_data(
    data: tuple[
        list[FakeDockerContainer],
        list[containers.ParsedContainer],
        config.AutheliaPolicy,
        rules.AccessControl,
    ],
) -> None:
    parsed_containers: list[containers.ParsedContainer]
    expected_access_control: rules.AccessControl
    _, parsed_containers, default_rule_policy, expected_access_control = data

    actual_access_control_dict = entry.to_authelia_data(
        parsed_containers=parsed_containers,
        default_authelia_policy=expected_access_control.default_policy,
        default_rule_policy=default_rule_policy,
    )

    expected_access_control_dict = dataclasses.asdict(
        expected_access_control, dict_factory=rules.enum_as_value_factory
    )

    assert actual_access_control_dict == expected_access_control_dict


# TODO: test invalid data
