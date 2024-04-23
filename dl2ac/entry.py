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

from dl2ac import config, models

app = typer.Typer()


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
def run_once(
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
) -> None:
    logger.remove()
    logger.add(sys.stderr, level=log_level.value)

    dynamic_config = create_dynamic_config(
        authelia_config_file,
        default_authelia_policy,
        default_rule_policy,
        environment,
        rules_file,
        None,
        None,
    )

    client: DockerClient = docker.from_env()
    parsed_containers = load_containers(client)
    sorted_rules = to_rules(parsed_containers, dynamic_config)
    access_control_dict = to_authelia_data(sorted_rules, dynamic_config)
    models.write_config(
        access_control_dict,
        config_file=dynamic_config.authelia_config_file,
        backup_config_file=dynamic_config.backup_config_file,
    )
    models.write_rules(sorted_rules, rules_file=dynamic_config.rules_file)
    models.restart_containers(parsed_containers)


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

    last_written_data: dict | None = None
    is_first_loop = True
    while True:
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

        parsed_containers = load_containers(client)

        if not models.has_authelia_containers(parsed_containers):
            logger.warning('No Authelia container found')
            continue

        sorted_rules = to_rules(parsed_containers, dynamic_config)
        access_control_dict = to_authelia_data(sorted_rules, dynamic_config)

        if last_written_data is not None and last_written_data == access_control_dict:
            logger.info(
                'Data did not change since last write. Skipping Re-Writing and Re-Starting.'
            )
            continue

        models.write_config(
            access_control_dict,
            config_file=dynamic_config.authelia_config_file,
            backup_config_file=dynamic_config.backup_config_file,
        )
        models.write_rules(sorted_rules, rules_file=dynamic_config.rules_file)
        models.restart_containers(parsed_containers)


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


def load_containers(client: DockerClient) -> list[models.ParsedContainer]:
    docker_containers: list[DockerContainer] = client.containers.list()
    logger.info(f'Found {len(docker_containers)} containers')

    raw_containers: list[models.RawContainer] = models.load_containers(
        docker_containers
    )
    logger.debug(f'{raw_containers=}')

    parsed_containers: list[models.ParsedContainer] = models.parse_containers(
        raw_containers
    )
    logger.debug(f'{parsed_containers=}')

    return parsed_containers


def to_rules(
    parsed_containers: list[models.ParsedContainer],
    dynamic_config: config.DynamicConfig,
) -> list[models.SortedRule]:
    all_labels: list[models.RuleLabel] = models.load_rules(parsed_containers)
    logger.debug(f'{all_labels=}')

    parsed_rules: list[models.ParsedRule] = models.parse_rules(
        all_labels, dynamic_config.default_rule_policy
    )
    logger.debug(f'{parsed_rules=}')

    sorted_rules: list[models.SortedRule] = models.sort_rules(parsed_rules)
    logger.debug(f'{sorted_rules=}')

    return sorted_rules


def to_authelia_data(
    sorted_rules: list[models.SortedRule], dynamic_config: config.DynamicConfig
) -> dict:
    access_control = models.to_access_control(
        sorted_rules, dynamic_config.default_authelia_policy
    )
    logger.debug(f'{access_control=}')

    access_control_dict = dataclasses.asdict(
        access_control, dict_factory=models.enum_as_value_factory
    )
    logger.info(f'{access_control_dict=}')

    return access_control_dict


if __name__ == '__main__':
    app()
