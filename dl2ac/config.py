import re

from loguru import logger


LABEL_START = 'dl2ac'

# 'dl2ac.is-authelia': true
AUTHELIA_KEY = rf'{LABEL_START}\.is-authelia'
AUTHELIA_VALUE = 'true'

logger.info(f'{AUTHELIA_KEY=}')
logger.info(f'{AUTHELIA_VALUE=}')

LABEL_RULES_START = rf'{LABEL_START}\.rules\.(.+)'

# 'dl2ac.rules.one.policy': 'one_factor'
POLICY_KEY_REGEX = re.compile(rf'{LABEL_RULES_START}\.policy')

# 'dl2ac.rules.one.priority': '20'
PRIORITY_KEY_REGEX = re.compile(rf'{LABEL_RULES_START}\.priority')
