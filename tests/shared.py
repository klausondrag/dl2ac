import time
from pathlib import Path

from hypothesis import strategies as st
from ruamel.yaml import YAML


rule_name_strategy = st.text(
    alphabet=st.characters(exclude_characters=['.', '\n']), min_size=1
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
    yaml = YAML()

    wait_for_file(actual_file)
    with open(actual_file, 'r') as file:
        actual_file_content = yaml.load(file)

    wait_for_file(expected_file)
    with open(expected_file, 'r') as file:
        expected_file_content = yaml.load(file)

    assert actual_file_content == expected_file_content
