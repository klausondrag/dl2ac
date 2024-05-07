import os
from collections.abc import Generator

import pytest
import subprocess
from pathlib import Path

from _pytest.fixtures import SubRequest
from typer.testing import CliRunner

from dl2ac import config, entry
from tests import shared


runner = CliRunner()
actual_rules_file = config.RuntimeEnvironment.DEV_LOCAL.value.rules_file


@pytest.fixture(scope='function', params=['./docker/docker-compose.dev.yml'])
def docker_compose_setup(request: SubRequest) -> Generator[Path, None, None]:
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
            'up',
            '-d',
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
    max_iterations = 1
    result = runner.invoke(
        entry.app,
        [
            '--log-level',
            'debug',
            '--sleep-at-start-n-seconds',
            shared.sleep_at_start_n_seconds,
            '--environment',
            config.RuntimeEnvironmentCli.DEV_LOCAL.value,
            '--max-iterations',
            str(max_iterations),
        ],
    )
    assert result.exit_code == 0
    assert entry.regular_exit_message.format(max_iterations) in result.stdout
    shared.assert_file_contents(actual_rules_file, expected_rules_file)
