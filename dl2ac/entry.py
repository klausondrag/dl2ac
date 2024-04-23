import dataclasses
import enum
import sys
from pathlib import Path
from typing import Optional

import docker
import typer
from docker.models.containers import Container as DockerContainer
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
def entry(
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
    log_level: Annotated[LogLevel, typer.Option(case_sensitive=False)] = LogLevel.INFO,
) -> None:
    logger.remove()
    logger.add(sys.stderr, level=log_level.value)

    runtime_environment_overrides = config.DynamicConfigOverrides(
        source_description='runtime-environment',
        default_authelia_policy=None,
        default_rule_policy=None,
        environment=None,
        authelia_config_file=None,
        rules_file=None,
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
        )

    cli_overrides = config.DynamicConfigOverrides(
        source_description='cli-arguments',
        default_authelia_policy=default_authelia_policy,
        default_rule_policy=default_rule_policy,
        environment=environment,
        authelia_config_file=authelia_config_file,
        rules_file=rules_file,
    )
    dynamic_config = config.DynamicConfig.load(
        defaults=config.defaults,
        overrides=[
            cli_overrides,
            config.environment_overrides,
            runtime_environment_overrides,
        ],
    )

    client = docker.from_env()
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

    all_labels: list[models.RuleLabel] = models.load_rules(parsed_containers)
    logger.debug(f'{all_labels=}')

    parsed_rules: list[models.ParsedRule] = models.parse_rules(
        all_labels, dynamic_config.default_rule_policy
    )
    logger.debug(f'{parsed_rules=}')

    sorted_rules: list[models.SortedRule] = models.sort_rules(parsed_rules)
    logger.debug(f'{sorted_rules=}')

    access_control = models.to_access_control(
        sorted_rules, dynamic_config.default_authelia_policy
    )
    logger.debug(f'{access_control=}')

    access_control_dict = dataclasses.asdict(
        access_control, dict_factory=models.enum_as_value_factory
    )
    logger.info(f'{access_control_dict=}')

    models.write_config(
        access_control_dict,
        config_file=dynamic_config.authelia_config_file,
        backup_config_file=dynamic_config.backup_config_file,
    )
    models.write_rules(sorted_rules, rules_file=dynamic_config.rules_file)

    models.restart_containers(parsed_containers)


if __name__ == '__main__':
    app()
