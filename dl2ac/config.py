import dataclasses
import enum
import os
import re
from pathlib import Path
from typing import Self, TypeVar, Any

from loguru import logger


LABEL_START = 'dl2ac'

# 'dl2ac.is-authelia': true
IS_AUTHELIA_KEY = f'{LABEL_START}.is-authelia'
IS_AUTHELIA_VALUE = 'true'

logger.debug(f'{IS_AUTHELIA_KEY=}')
logger.debug(f'{IS_AUTHELIA_VALUE=}')

LABEL_RULES_START_REGEX = rf'{LABEL_START}\.rules\.(.+)'
LABEL_RULES_START_FORMAT = f'{LABEL_START}.rules.{{rule_name}}'

# 'dl2ac.rules.one.methods.1': 'OPTIONS'
METHODS_KEY_REGEX = re.compile(rf'{LABEL_RULES_START_REGEX}\.methods\.(.+)')
METHODS_KEY_FORMAT = f'{LABEL_RULES_START_FORMAT}.methods.{{index}}'

# 'dl2ac.rules.one.policy': 'one_factor'
POLICY_KEY_REGEX = re.compile(rf'{LABEL_RULES_START_REGEX}\.policy')
POLICY_KEY_FORMAT = f'{LABEL_RULES_START_FORMAT}.policy'

# 'dl2ac.rules.one.rank': '20'
RANK_KEY_REGEX = re.compile(rf'{LABEL_RULES_START_REGEX}\.rank')
RANK_KEY_FORMAT = f'{LABEL_RULES_START_FORMAT}.rank'

# 'dl2ac.rules.one.subjects.1.1': 'user:john'
SUBJECT_KEY_REGEX = re.compile(rf'{LABEL_RULES_START_REGEX}\.subject\.(.+)\.(.+)')
SUBJECT_KEY_FORMAT = (
    f'{LABEL_RULES_START_FORMAT}.subject.{{outer_index}}.{{inner_index}}'
)

UPDATE_YAML_KEY = 'access_control'


# Reference: https://www.authelia.com/configuration/security/access-control/#policies
class AutheliaPolicy(str, enum.Enum):
    DENY = 'deny'
    BYPASS = 'bypass'
    ONE_FACTOR = 'one_factor'
    TWO_FACTOR = 'two_factor'


T = TypeVar('T', bound=enum.Enum)


def allowed_enum_values(enum_type: type[T]) -> str:
    return ', '.join(f'`{enum_entry.value}`' for enum_entry in enum_type)


allowed_authelia_policy_values = allowed_enum_values(AutheliaPolicy)
logger.debug(f'Allowed Authelia Policy Values: {allowed_authelia_policy_values}')


@dataclasses.dataclass
class RuntimeEnvironmentConfig:
    name: str  # Add name because enum values must be unique. Duplicate enum names will be removed.
    authelia_config_file: Path
    rules_file: Path


class RuntimeEnvironment(enum.Enum):
    DEV_LOCAL = RuntimeEnvironmentConfig(
        name='dev-local',
        authelia_config_file=Path('./dev/local/configuration.yml'),
        rules_file=Path('./dev/local/rules.yml'),
    )
    DEV_DOCKER = RuntimeEnvironmentConfig(
        name='dev-docker',
        authelia_config_file=Path('/config/configuration.yml'),
        rules_file=Path('/rules/rules.yml'),
    )
    PROD_DOCKER = RuntimeEnvironmentConfig(
        name='prod-docker',
        authelia_config_file=Path('/config/configuration.yml'),
        rules_file=Path('/rules/rules.yml'),
    )


class RuntimeEnvironmentCli(str, enum.Enum):
    DEV_LOCAL = 'dev-local'
    DEV_DOCKER = 'dev-docker'
    PROD_DOCKER = 'prod-docker'

    def to_runtime_environment(self) -> RuntimeEnvironment:
        if self == RuntimeEnvironmentCli.DEV_LOCAL:
            return RuntimeEnvironment.DEV_LOCAL
        elif self == RuntimeEnvironmentCli.DEV_DOCKER:
            return RuntimeEnvironment.DEV_DOCKER
        elif self == RuntimeEnvironmentCli.PROD_DOCKER:
            return RuntimeEnvironment.PROD_DOCKER
        else:
            logger.warning(
                f'[Development] Could not convert `RuntimeEnvironmentCli` to `RuntimeEnvironment`'
                f' because of unknown RuntimeEnvironmentCli value: {self}.'
                f' Defaulting to RuntimeEnvironment.PROD_DOCKER. Please report this issue.'
            )
            return RuntimeEnvironment.PROD_DOCKER


allowed_environment_values = allowed_enum_values(RuntimeEnvironmentCli)
logger.debug(f'Allowed Runtime Environment Values: {allowed_environment_values}')


runtime_environment_fields = {
    runtime_environment.name for runtime_environment in RuntimeEnvironment
}
runtime_environment_cli_fields = {
    runtime_environment_cli.name for runtime_environment_cli in RuntimeEnvironmentCli
}

if runtime_environment_fields != runtime_environment_cli_fields:
    logger.warning(
        '[Development] `RuntimeEnvironment` and `RuntimeEnvironmentCli` must have the same fields,'
        + ' but they do not. Please report this issue.'
        + f' {runtime_environment_fields=}, {runtime_environment_cli_fields=}.'
        + f' Only in RuntimeEnvironment: {runtime_environment_fields-runtime_environment_cli_fields}.'
        + f' Only in RuntimeEnvironmentCli: {runtime_environment_cli_fields-runtime_environment_fields}.'
    )


def get_enum_from_env(key: str, enum_type: type[T], allowed_values: str) -> T | None:
    value = os.environ.get(key)
    if value is None:
        return None

    try:
        return enum_type[value.upper()]
    except KeyError:
        logger.warning(
            f'Found environment variable {key}, but cannot parse its value as {enum_type}.'
            + f' Must be one of [{allowed_values}]. Skipping it.'
        )

    return None


def get_int_from_env(key: str) -> int | None:
    value = os.environ.get(key)
    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        logger.warning(
            f'Found environment variable {key}, but cannot parse its value as an integer. Skipping it.'
        )

    return None


def get_path_from_env(key: str) -> Path | None:
    value = os.environ.get(key)
    if value is None:
        return None

    return Path(value)


@dataclasses.dataclass
class DynamicConfigOverrides:
    default_authelia_policy: AutheliaPolicy | None
    default_rule_policy: AutheliaPolicy | None
    environment: RuntimeEnvironmentCli | None
    authelia_config_file: Path | None
    rules_file: Path | None
    sleep_at_start_n_seconds: int | None
    sleep_interval_n_seconds: int | None
    source_description: str


runtime_environment_from_env = get_enum_from_env(
    'ENVIRONMENT', RuntimeEnvironmentCli, allowed_environment_values
)
authelia_config_file_from_env = get_path_from_env('AUTHELIA_CONFIG_PATH')
rules_file_from_env = get_path_from_env('AUTHELIA_CONFIG_PATH')
if runtime_environment_from_env is not None:
    runtime_value = runtime_environment_from_env.to_runtime_environment().value
    if authelia_config_file_from_env is None:
        authelia_config_file_from_env = runtime_value.authelia_config_file

    if rules_file_from_env is None:
        rules_file_from_env = runtime_value.rules_file


environment_overrides = DynamicConfigOverrides(
    source_description='environment',
    default_authelia_policy=get_enum_from_env(
        'DEFAULT_AUTHELIA_POLICY', AutheliaPolicy, allowed_authelia_policy_values
    ),
    default_rule_policy=get_enum_from_env(
        'DEFAULT_RULE_POLICY', AutheliaPolicy, allowed_authelia_policy_values
    ),
    environment=runtime_environment_from_env,
    authelia_config_file=authelia_config_file_from_env,
    rules_file=rules_file_from_env,
    sleep_at_start_n_seconds=get_int_from_env('SLEEP_AT_START_N_SECONDS'),
    sleep_interval_n_seconds=get_int_from_env('SLEEP_INTERVAL_N_SECONDS'),
)


@dataclasses.dataclass
class DynamicConfig:
    default_authelia_policy: AutheliaPolicy
    default_rule_policy: AutheliaPolicy
    environment: RuntimeEnvironmentCli
    authelia_config_file: Path
    rules_file: Path
    sleep_at_start_n_seconds: int
    sleep_interval_n_seconds: int

    @property
    def backup_config_file(self) -> Path:
        return (
            self.authelia_config_file.parent
            / f'{self.authelia_config_file.stem}_bak{self.authelia_config_file.suffix}'
        )

    @classmethod
    def load(cls, defaults: Self, overrides: list[DynamicConfigOverrides]) -> Self:
        logger.debug(
            'Loading dynamic config.'
            + f'default_values={defaults}'
            + f', overrides={overrides}'
        )

        field_names = [field.name for field in dataclasses.fields(cls)]
        kwargs = {
            field_name: _load_from(
                field_name,
                defaults=defaults,
                overrides=overrides,
            )
            for field_name in field_names
        }
        final_config = cls(**kwargs)
        logger.info(f'Loaded Configuration: {final_config}')
        return final_config


def _load_from(
    field_name: str, defaults: DynamicConfig, overrides: list[DynamicConfigOverrides]
) -> Any:
    for override in overrides:
        try:
            value = getattr(override, field_name)
            if value is not None:
                logger.debug(
                    f'Loaded {field_name}={value} from {override.source_description}'
                )
                return value
        except AttributeError:
            logger.warning(
                f'Could not find attribute {field_name} in {override.source_description} config object'
            )

    try:
        value = getattr(defaults, field_name)
        logger.debug(f'Loaded {field_name}={value} from defaults')
        if value is not None:
            return value
    except AttributeError:
        logger.warning(
            f'Could not find attribute {field_name} in defaults config object'
        )

    logger.warning(
        f'[Development] Could not find attribute {field_name} in any config object.'
        + ' Returning `None`. Please report this issue.'
    )
    return None


defaults = DynamicConfig(
    default_authelia_policy=AutheliaPolicy.DENY,
    default_rule_policy=AutheliaPolicy.DENY,
    environment=RuntimeEnvironmentCli.PROD_DOCKER,
    authelia_config_file=RuntimeEnvironmentCli.PROD_DOCKER.to_runtime_environment().value.authelia_config_file,
    rules_file=RuntimeEnvironmentCli.PROD_DOCKER.to_runtime_environment().value.rules_file,
    sleep_at_start_n_seconds=5,
    sleep_interval_n_seconds=60,
)

defaults_fields = {field.name for field in dataclasses.fields(defaults)}
environment_fields = {
    field.name
    for field in dataclasses.fields(environment_overrides)
    if field.name != 'source_description'
}
if defaults_fields != environment_fields:
    logger.warning(
        '[Development] `DynamicConfig` and `DynamicConfigOverrides` must have the same fields,'
        + ' but they do not. Please report this issue.'
        + f' {defaults_fields=}, {environment_fields=}.'
        + f' Only in DynamicConfig: {defaults_fields-environment_fields}.'
        + f' Only in DynamicConfigOverrides: {environment_fields-defaults_fields}.'
    )
