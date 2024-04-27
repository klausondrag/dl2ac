import os
import time

import pytest
import subprocess
from pathlib import Path

from ruamel.yaml import YAML


# From docker compose file
actual_rules_file = Path('./dev/docker/rules/rules.yml')


@pytest.fixture(scope='function')
def set_env(monkeypatch):
    monkeypatch.setenv('SLEEP_AT_START_N_SECONDS', '1')


@pytest.fixture(scope='function', params=['./docker/docker-compose.dev.yml'])
def docker_compose_setup(request, set_env):
    actual_rules_file.unlink(missing_ok=True)
    docker_compose_file = request.param
    base_file = Path(docker_compose_file)
    expected_output_file = (
        base_file.parent / f'{base_file.stem}.expected-output{base_file.suffix}'
    )
    subprocess.call(
        [
            'docker',
            'compose',
            '-f',
            docker_compose_file,
            '--profile',
            'dev-docker',
            'up',
            '-d',
        ]
    )
    try:
        yield expected_output_file
    finally:
        subprocess.call(['docker', 'compose', '-f', docker_compose_file, 'down'])


def wait_for_file(file: Path, max_tries=10) -> None:
    current_try = 0
    while current_try < max_tries and (not file.exists() or file.stat().st_size == 0):
        current_try += 1
        time.sleep(1)

    assert file.exists()
    assert file.stat().st_size > 0


@pytest.mark.skipif(
    os.getenv('DL2AC_RUN_INTEGRATION_TESTS') != '1',
    reason='Only run integration tests in CI because they are slow.',
)
def test_rules(docker_compose_setup):
    yaml = YAML()
    wait_for_file(actual_rules_file)
    with open(actual_rules_file, 'r') as file:
        actual_rules = yaml.load(file)

    expected_rules_file: Path = docker_compose_setup
    wait_for_file(expected_rules_file)
    with open(expected_rules_file, 'r') as file:
        expected_rules = yaml.load(file)

    assert actual_rules == expected_rules
