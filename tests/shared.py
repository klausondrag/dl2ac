import time
from pathlib import Path
from typing import Any

from hypothesis import strategies as st

from dl2ac import config, labels, rules


container_name_strategy = st.text()
rule_name_strategy = st.text(
    alphabet=st.characters(exclude_characters=['.', '\n']), min_size=1
)
traefik_router_name_strategy = rule_name_strategy
index_strategy = st.integers()

is_authelia_strategy = st.booleans()
domain_strategy = st.text(alphabet=st.characters(exclude_characters=['\n']), min_size=1)
domain_regex_strategy = domain_strategy
methods_strategy = st.sampled_from(labels.AutheliaMethod)
policy_strategy = st.sampled_from(config.AutheliaPolicy)
rank_strategy = st.integers()
resources_strategy = domain_strategy
query_key_strategy = domain_strategy
query_operator_strategy = st.sampled_from(labels.AutheliaOperator)
query_value_strategy = domain_strategy
subject_strategy = resources_strategy


@st.composite
def query_object_strategy(
    draw: st.DrawFn,
) -> labels.QueryObject:
    # For omitting rules, see https://www.authelia.com/configuration/security/access-control/#query
    # key: required
    # value: This is required unless the operator is absent or present
    # operator: If key and value are specified this defaults to equal,
    # otherwise if key is specified it defaults to present.

    key = draw(query_key_strategy)
    operator = draw(query_operator_strategy)
    value = None
    if operator == labels.AutheliaOperator.ABSENT:
        value = None
    elif operator == labels.AutheliaOperator.PRESENT:
        value = None
        if draw(st.booleans()):
            operator = None
    elif operator == labels.AutheliaOperator.EQUAL:
        value = draw(query_value_strategy)
        if draw(st.booleans()):
            operator = None

    query_object = labels.QueryObject(
        key=key,
        operator=operator,
        value=value,
    )
    return query_object


is_authelia_label_strategy = st.builds(
    labels.IsAutheliaLabel,
    is_authelia=is_authelia_strategy,
)

traefik_router_label_strategy = st.builds(
    labels.TraefikRouterLabel,
    traefik_router_name=traefik_router_name_strategy,
    domain=domain_strategy,
)

domain_label_strategy = st.builds(
    labels.DomainLabel,
    rule_name=rule_name_strategy,
    index=index_strategy,
    domain=domain_strategy,
)

domain_add_traefik_label_strategy = st.builds(
    labels.DomainAddTraefikLabel,
    rule_name=rule_name_strategy,
    index=index_strategy,
    traefik_router_name=traefik_router_name_strategy,
)

domain_from_traefik_label_strategy = st.builds(
    labels.DomainFromTraefikLabel,
    rule_name=rule_name_strategy,
    index=index_strategy,
    domain=domain_strategy,
)

domain_regex_label_strategy = st.builds(
    labels.DomainRegexLabel,
    rule_name=rule_name_strategy,
    index=index_strategy,
    domain_regex=domain_regex_strategy,
)

methods_label_strategy = st.builds(
    labels.MethodsLabel,
    rule_name=rule_name_strategy,
    index=index_strategy,
    method=methods_strategy,
)

policy_label_strategy = st.builds(
    labels.PolicyLabel,
    rule_name=rule_name_strategy,
    policy=policy_strategy,
)

query_label_strategy = st.builds(
    labels.QueryLabel,
    rule_name=rule_name_strategy,
    outer_index=index_strategy,
    inner_index=index_strategy,
    query=query_object_strategy(),
)

query_key_label_strategy = st.builds(
    labels.QueryKeyLabel,
    rule_name=rule_name_strategy,
    outer_index=index_strategy,
    inner_index=index_strategy,
    key=query_key_strategy,
)

query_operator_label_strategy = st.builds(
    labels.QueryOperatorLabel,
    rule_name=rule_name_strategy,
    outer_index=index_strategy,
    inner_index=index_strategy,
    operator=query_operator_strategy,
)

query_value_label_strategy = st.builds(
    labels.QueryKeyLabel,
    rule_name=rule_name_strategy,
    outer_index=index_strategy,
    inner_index=index_strategy,
    value=query_value_strategy,
)

rank_label_strategy = st.builds(
    labels.RankLabel,
    rule_name=rule_name_strategy,
    rank=rank_strategy,
)

resources_label_strategy = st.builds(
    labels.ResourcesLabel,
    rule_name=rule_name_strategy,
    index=index_strategy,
    resource=resources_strategy,
)

subject_label_strategy = st.builds(
    labels.SubjectLabel,
    rule_name=rule_name_strategy,
    outer_index=index_strategy,
    inner_index=index_strategy,
    subject=subject_strategy,
)

parsable_label_strategy = st.one_of(
    is_authelia_label_strategy,
    traefik_router_label_strategy,
    domain_label_strategy,
    domain_add_traefik_label_strategy,
    domain_regex_label_strategy,
    methods_label_strategy,
    policy_label_strategy,
    rank_label_strategy,
    resources_label_strategy,
    subject_label_strategy,
)

sleep_at_start_n_seconds = '1'


def wait_for_file(file: Path, max_tries: int = 10) -> None:
    current_try = 0
    while current_try < max_tries and (not file.exists() or file.stat().st_size == 0):
        current_try += 1
        time.sleep(1)

    assert file.exists()
    assert file.stat().st_size > 0


def assert_file_contents(actual_file: Path, expected_file: Path) -> None:
    yaml = rules.StringYaml()

    wait_for_file(actual_file)
    with open(actual_file, 'r') as file:
        actual_file_content: Any = yaml.load(file)

    wait_for_file(expected_file)
    with open(expected_file, 'r') as file:
        expected_file_content: Any = yaml.load(file)

    assert actual_file_content == expected_file_content
