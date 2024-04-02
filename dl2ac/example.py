import enum
import sys

import typer
from loguru import logger
from typing_extensions import Annotated

app = typer.Typer()


class LogLevel(str, enum.Enum):
    TRACE = 'TRACE'
    DEBUG = 'DEBUG'
    INFO = 'INFO'
    SUCCESS = 'SUCCESS'
    WARNING = 'WARNING'
    ERROR = 'ERROR'
    CRITICAL = 'CRITICAL'


@app.command()
def hello() -> None:
    name = decode([('W', 1), ('o', 1), ('r', 1), ('l', 1), ('d', 1)])
    print(f'Hello, {name}!')


@app.command()
def goodbye(
    name: str,
    log_level: Annotated[LogLevel, typer.Option(case_sensitive=False)] = LogLevel.INFO,
) -> None:
    logger.remove()
    logger.add(sys.stderr, level=log_level.value)
    logger.debug(encode(name))
    print(f'Goodbye, {name}!')
    logger.success('done')


def encode(input_string):
    if not input_string:
        return []

    count = 1
    prev = ''
    lst = []
    character = ''
    for character in input_string:
        if character != prev:
            if prev:
                entry = (prev, count)
                lst.append(entry)
            count = 1
            prev = character
        else:
            count += 1

    entry = (character, count)
    lst.append(entry)
    return lst


def decode(lst):
    q = ''
    for character, count in lst:
        q += character * count
    return q


if __name__ == '__main__':
    app()
