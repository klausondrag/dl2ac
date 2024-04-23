#!/usr/bin/env just --justfile

p_run := "poetry run"

default: format pre-commit test

alias f := format
alias fmt := format
alias pc := pre-commit
alias r := run
alias t := test

format:
    {{p_run}} ruff format
    {{p_run}} pyright

# If the command was not successful
# perhaps some errors were fixed automatically.
# In that case, try again.
pre-commit:
    if ! {{p_run}} pre-commit run --all-files; then \
      {{p_run}} pre-commit run --all-files; \
    fi

setup-dev:
    poetry install --with dev
    {{p_run}} pre-commit install
    {{p_run}} pre-commit run --all-files

test:
    {{p_run}} pytest --cov=dl2ac

run *ARGS:
    {{p_run}} python3 cli.py {{ARGS}}

run-example:
    just run example hello
    just run example goodbye "World" --log-level "debug"

dev-start:
	docker compose -f docker/docker-compose.dev.yml up -d

dev-stop:
	docker compose -f docker/docker-compose.dev.yml down

run-dl2ac:
    rm ./dev/*.yml -f
    cp ./authelia-configs/default-configuration_4.38.7.yml ./dev/configuration.yml
    just run entry entry --log-level "debug" --environment "dev-local"

extract-default-config:
	./extract_default_config.sh
