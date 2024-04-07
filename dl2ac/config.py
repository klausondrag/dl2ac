import dataclasses
import enum
import os
import re
from typing import Self

from loguru import logger

LABEL_START = 'dl2ac'

# 'dl2ac.is-authelia': true
IS_AUTHELIA_KEY = f'{LABEL_START}.is-authelia'
IS_AUTHELIA_VALUE = 'true'

logger.info(f'{IS_AUTHELIA_KEY=}')
logger.info(f'{IS_AUTHELIA_VALUE=}')

LABEL_RULES_START_REGEX = rf'{LABEL_START}\.rules\.(.+)'
LABEL_RULES_START_FORMAT = f'{LABEL_START}.rules.{{rule_name}}'

# 'dl2ac.rules.one.policy': 'one_factor'
POLICY_KEY_REGEX = re.compile(rf'{LABEL_RULES_START_REGEX}\.policy')
POLICY_KEY_FORMAT = f'{LABEL_RULES_START_FORMAT}.policy'

# 'dl2ac.rules.one.priority': '20'
PRIORITY_KEY_REGEX = re.compile(rf'{LABEL_RULES_START_REGEX}\.priority')
PRIORITY_KEY_FORMAT = f'{LABEL_RULES_START_FORMAT}.priority'


# Reference: https://www.authelia.com/configuration/security/access-control/#policies
class AutheliaPolicy(str, enum.Enum):
    DENY = 'deny'
    BYPASS = 'bypass'
    ONE_FACTOR = 'one_factor'
    TWO_FACTOR = 'two_factor'


allowed_authelia_policy_values = ', '.join(
    f'`{policy.value}`' for policy in AutheliaPolicy
)
logger.info(f'Allowed Authelia Policy Values: {allowed_authelia_policy_values}')


def get_enum_from_env(key: str) -> AutheliaPolicy | None:
    try:
        value = os.environ.get(key)
        if value is None:
            return None

        return AutheliaPolicy[value.upper()]
    except KeyError:
        logger.warning(
            f'Found environment variable {key}, but cannot parse its value as an  as a policy.'
            + f' Must be one of [{allowed_authelia_policy_values}]. Skipping it.'
        )

    return None


def get_int_from_env(key: str) -> int | None:
    try:
        value = os.environ.get(key)
        if value is None:
            return None

        return int(value)
    except ValueError:
        logger.warning(
            f'Found environment variable {key}, but cannot parse its value as an integer. Skipping it.'
        )

    return None


@dataclasses.dataclass
class DynamicConfigOverrides:
    default_priority: int | None
    default_rule_policy: AutheliaPolicy | None


environment = DynamicConfigOverrides(
    default_priority=get_int_from_env('DEFAULT_PRIORITY'),
    default_rule_policy=get_enum_from_env('DEFAULT_RULE_POLICY'),
)


@dataclasses.dataclass
class DynamicConfig:
    default_priority: int
    default_rule_policy: AutheliaPolicy

    @classmethod
    def load(
        cls,
        cli_overrides: DynamicConfigOverrides,
        environment_overrides: DynamicConfigOverrides,
        defaults: Self,
    ) -> Self:
        logger.debug(
            'Loading dynamic config.'
            + f'default_values={defaults}'
            + f', environment_values={environment_overrides}'
            + f', cli_values={cli_overrides}'
        )

        if cli_overrides.default_priority is not None:
            default_priority = cli_overrides.default_priority
            logger.info(f'Loaded {default_priority=} from cli')
        elif environment_overrides.default_priority is not None:
            default_priority = environment_overrides.default_priority
            logger.info(f'Loaded {default_priority=} from environment')
        else:
            default_priority = defaults.default_priority
            logger.info(f'Loaded {default_priority=} from defaults')

        if cli_overrides.default_rule_policy is not None:
            default_rule_policy = cli_overrides.default_rule_policy
            logger.info(f'Loaded {default_rule_policy=} from cli')
        elif environment_overrides.default_rule_policy is not None:
            default_rule_policy = environment_overrides.default_rule_policy
            logger.info(f'Loaded {default_rule_policy=} from environment')
        else:
            default_rule_policy = defaults.default_rule_policy
            logger.info(f'Loaded {default_rule_policy=} from defaults')

        return cls(
            default_priority=default_priority, default_rule_policy=default_rule_policy
        )


defaults = DynamicConfig(
    default_priority=100,
    default_rule_policy=AutheliaPolicy.DENY,
)
