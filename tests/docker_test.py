import os
from collections.abc import Generator

import pytest
import subprocess
from pathlib import Path

from _pytest.fixtures import SubRequest
from _pytest.monkeypatch import MonkeyPatch

from tests import shared


# From docker compose file
actual_rules_file = Path('./dev/docker/rules/rules.yml')


@pytest.fixture(scope='function')
def set_env(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv('SLEEP_AT_START_N_SECONDS', shared.sleep_at_start_n_seconds)


@pytest.fixture(scope='function', params=['./docker/docker-compose.dev.yml'])
def docker_compose_setup(
    request: SubRequest, set_env: None
) -> Generator[Path, None, None]:
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
            '--build',
        ]
    )
    try:
        yield expected_output_file
    finally:
        subprocess.call(['docker', 'compose', '-f', docker_compose_file, 'down'])


@pytest.mark.skipif(
    os.getenv('DL2AC_RUN_INTEGRATION_TESTS') != '1',
    reason='Only run integration tests in CI because they are slow.',
)
def test_rules(docker_compose_setup: Path) -> None:
    expected_rules_file: Path = docker_compose_setup
    shared.assert_file_contents(expected_rules_file, actual_rules_file)
