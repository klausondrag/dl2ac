import dataclasses
import enum
import sys
import time
from pathlib import Path
from typing import Optional

import docker
import typer
from docker.models.containers import Container as DockerContainer
from docker.client import DockerClient
from loguru import logger
from typing_extensions import Annotated

from dl2ac import config, containers, labels, rules


app = typer.Typer()
regular_exit_message = 'Finished program because max iterations (={}) has been reached.'


class LogLevel(str, enum.Enum):
    TRACE = 'TRACE'
    DEBUG = 'DEBUG'
    INFO = 'INFO'
    SUCCESS = 'SUCCESS'
    WARNING = 'WARNING'
    ERROR = 'ERROR'
    CRITICAL = 'CRITICAL'


# typer does not support the syntax `Path | None` yet.
# So, we use Optional[Path] instead.
# See https://github.com/tiangolo/typer/issues/533
@app.command()
def run_loop(
    log_level: Annotated[LogLevel, typer.Option(case_sensitive=False)] = LogLevel.INFO,
    environment: Annotated[
        Optional[config.RuntimeEnvironmentCli], typer.Option(case_sensitive=False)
    ] = None,
    default_authelia_policy: Annotated[
        Optional[config.AutheliaPolicy], typer.Option(case_sensitive=False)
    ] = None,
    default_rule_policy: Annotated[
        Optional[config.AutheliaPolicy], typer.Option(case_sensitive=False)
    ] = None,
    authelia_config_file: Annotated[Optional[Path], typer.Option()] = None,
    rules_file: Annotated[Optional[Path], typer.Option()] = None,
    sleep_at_start_n_seconds: Annotated[Optional[int], typer.Option(min=0)] = None,
    sleep_interval_n_seconds: Annotated[Optional[int], typer.Option(min=0)] = None,
    max_iterations: Annotated[Optional[int], typer.Option(min=-1)] = None,
) -> None:
    logger.remove()
    logger.add(sys.stderr, level=log_level.value)

    dynamic_config = create_dynamic_config(
        authelia_config_file,
        default_authelia_policy,
        default_rule_policy,
        environment,
        rules_file,
        sleep_at_start_n_seconds,
        sleep_interval_n_seconds,
    )

    client = docker.from_env()

    if max_iterations is not None and max_iterations < 0:
        max_iterations = None

    last_written_data: dict | None = None
    is_first_loop = True
    current_iteration = 0
    while max_iterations is None or current_iteration < max_iterations:
        # Sleep at the start of the loop, so we can use the keyword `continue`
        sleep_n_seconds = (
            dynamic_config.sleep_at_start_n_seconds
            if is_first_loop
            else dynamic_config.sleep_interval_n_seconds
        )
        logger.info(f'Going to sleep for {sleep_n_seconds} seconds...')
        time.sleep(sleep_n_seconds)
        logger.info('Woke up. Continuing work...')
        is_first_loop = False

        # Avoid counting endlessly if we run in an endless loop
        current_iteration = 0 if max_iterations is None else current_iteration + 1

        parsed_containers = load_containers(client)

        if not containers.has_authelia_containers(parsed_containers):
            logger.warning('No Authelia container found')
            continue

        access_control_data = to_authelia_data(
            parsed_containers,
            dynamic_config.default_authelia_policy,
            dynamic_config.default_rule_policy,
        )

        if last_written_data is not None and last_written_data == access_control_data:
            logger.info(
                'Data did not change since last write. Skipping Re-Writing and Re-Starting.'
            )
            continue

        rules.write_config(
            access_control_data=access_control_data,
            config_file=dynamic_config.authelia_config_file,
            backup_config_file=dynamic_config.backup_config_file,
        )
        rules.write_access_control_data(
            access_control_data=access_control_data,
            rules_file=dynamic_config.rules_file,
        )
        containers.restart_containers(parsed_containers)

    logger.info(regular_exit_message, max_iterations)


def create_dynamic_config(
    authelia_config_file: Path | None,
    default_authelia_policy: config.AutheliaPolicy | None,
    default_rule_policy: config.AutheliaPolicy | None,
    environment: config.RuntimeEnvironmentCli | None,
    rules_file: Path | None,
    sleep_at_start_n_seconds: int | None,
    sleep_interval_n_seconds: int | None,
):
    runtime_environment_overrides = config.DynamicConfigOverrides(
        source_description='runtime-environment',
        default_authelia_policy=None,
        default_rule_policy=None,
        environment=None,
        authelia_config_file=None,
        rules_file=None,
        sleep_at_start_n_seconds=None,
        sleep_interval_n_seconds=None,
    )
    if environment is not None:
        runtime_value = environment.to_runtime_environment().value
        runtime_environment_overrides = config.DynamicConfigOverrides(
            source_description='runtime-environment',
            default_authelia_policy=None,
            default_rule_policy=None,
            environment=environment,
            authelia_config_file=runtime_value.authelia_config_file,
            rules_file=runtime_value.rules_file,
            sleep_at_start_n_seconds=None,
            sleep_interval_n_seconds=None,
        )

    cli_overrides = config.DynamicConfigOverrides(
        source_description='cli-arguments',
        default_authelia_policy=default_authelia_policy,
        default_rule_policy=default_rule_policy,
        environment=environment,
        authelia_config_file=authelia_config_file,
        rules_file=rules_file,
        sleep_at_start_n_seconds=sleep_at_start_n_seconds,
        sleep_interval_n_seconds=sleep_interval_n_seconds,
    )

    dynamic_config = config.DynamicConfig.load(
        defaults=config.defaults,
        overrides=[
            cli_overrides,
            config.environment_overrides,
            runtime_environment_overrides,
        ],
    )
    return dynamic_config


def load_containers(client: DockerClient) -> list[containers.ParsedContainer]:
    docker_containers: list[DockerContainer] = client.containers.list()
    logger.info(f'Found {len(docker_containers)} containers')

    raw_containers: list[containers.RawContainer] = containers.load_containers(
        docker_containers
    )
    logger.debug(f'{raw_containers=}')

    parsed_containers: list[containers.ParsedContainer] = containers.parse_containers(
        raw_containers
    )
    logger.debug(f'{parsed_containers=}')

    return parsed_containers


def to_authelia_data(
    parsed_containers: list[containers.ParsedContainer],
    default_authelia_policy: config.AutheliaPolicy,
    default_rule_policy: config.AutheliaPolicy,
) -> dict:
    raw_labels: list[labels.RawRuleLabel] = containers.load_rules(parsed_containers)
    logger.debug(f'{raw_labels=}')

    other_labels: list[labels.ParsedLabel] = containers.load_other_labels(
        parsed_containers
    )
    logger.debug(f'{other_labels=}')

    resolved_labels: list[labels.ResolvedRuleLabel] = labels.resolve(
        raw_labels, other_labels
    )
    logger.debug(f'{resolved_labels=}')

    parsed_rules: list[rules.ParsedRule] = rules.parse_rules(
        resolved_labels, default_rule_policy
    )
    logger.debug(f'{parsed_rules=}')

    sorted_rules: list[rules.SortedRule] = rules.sort_rules(parsed_rules)
    logger.debug(f'{sorted_rules=}')

    access_control = rules.to_access_control(sorted_rules, default_authelia_policy)
    logger.debug(f'{access_control=}')

    access_control_dict = dataclasses.asdict(
        access_control, dict_factory=rules.enum_as_value_factory
    )
    logger.info(f'{access_control_dict=}')

    return access_control_dict


if __name__ == '__main__':
    app()
