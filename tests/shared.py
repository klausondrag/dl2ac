import time
from pathlib import Path

from hypothesis import strategies as st

from dl2ac import config, models


container_name_strategy = st.text()
rule_name_strategy = st.text(
    alphabet=st.characters(exclude_characters=['.', '\n']), min_size=1
)
is_authelia_strategy = st.booleans()
index_strategy = st.integers()
method_value_strategy = st.sampled_from(models.AutheliaMethod)
policy_strategy = st.sampled_from(config.AutheliaPolicy)
rank_strategy = st.integers()
subject_strategy = st.text(
    alphabet=st.characters(exclude_characters=['\n']), min_size=1
)

method_label_strategy = st.builds(
    models.MethodLabel,
    rule_name=rule_name_strategy,
    index=index_strategy,
    method=method_value_strategy,
)

policy_label_strategy = st.builds(
    models.PolicyLabel,
    rule_name=rule_name_strategy,
    policy=policy_strategy,
)

rank_label_strategy = st.builds(
    models.RankLabel,
    rule_name=rule_name_strategy,
    rank=rank_strategy,
)

sleep_at_start_n_seconds = '1'


def wait_for_file(file: Path, max_tries=10) -> None:
    current_try = 0
    while current_try < max_tries and (not file.exists() or file.stat().st_size == 0):
        current_try += 1
        time.sleep(1)

    assert file.exists()
    assert file.stat().st_size > 0


def assert_file_contents(actual_file: Path, expected_file: Path) -> None:
    yaml = models.StringYaml()

    wait_for_file(actual_file)
    with open(actual_file, 'r') as file:
        actual_file_content = yaml.load(file)

    wait_for_file(expected_file)
    with open(expected_file, 'r') as file:
        expected_file_content = yaml.load(file)

    assert actual_file_content == expected_file_content
