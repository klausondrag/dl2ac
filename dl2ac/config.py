import re

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
