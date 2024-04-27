#!/usr/bin/env just --justfile

p_run := "poetry run"
authelia_config_file := "./authelia-configs/default-configuration_4.38.7.yml"
dev_local_path := "./dev/local"
dev_docker_path := "./dev/docker"

default: format pre-commit test-all

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
    {{p_run}} pytest --cov=dl2ac --hypothesis-profile dev

# Can use if interested: --hypothesis-show-statistics
test-all:
    DL2AC_RUN_INTEGRATION_TESTS=1 {{p_run}} pytest --cov=dl2ac --hypothesis-profile dev-all

run *ARGS:
    {{p_run}} python3 cli.py {{ARGS}}

run-example:
    just run example hello
    just run example goodbye "World" --log-level "debug"

dev-start:
	docker compose -f docker/docker-compose.dev.yml up -d

dev-stop:
	docker compose -f docker/docker-compose.dev.yml down
	docker compose -f docker/docker-compose.dev.yml rm

run-dl2ac-dev-local-once: dev-start && dev-stop
    rm {{dev_local_path}}/*.yml -f
    cp {{authelia_config_file}} {{dev_local_path}}/configuration.yml
    just run dl2ac run-once --log-level "debug" --environment "dev-local"

run-dl2ac-dev-local-loop: dev-start && dev-stop
    # trap doesn't seem to work with just
    # https://github.com/casey/just/issues/1560
    # trap 'echo "todo: dev-stop"' INT TERM
    rm {{dev_local_path}}/*.yml -f
    cp {{authelia_config_file}} {{dev_local_path}}/configuration.yml
    just run dl2ac run-loop --log-level "debug" --environment "dev-local" \
      --sleep-at-start-n-seconds 2 --sleep-interval-n-seconds 5

run-dl2ac-dev-docker-loop: && dev-stop
    rm {{dev_docker_path}}/config/*.yml -f
    rm {{dev_docker_path}}/rules/*.yml -f
    cp {{authelia_config_file}} {{dev_docker_path}}/config/configuration.yml
    docker compose --file docker/docker-compose.dev.yml --profile dev-docker up --build

extract-default-config:
	./extract_default_config.sh
