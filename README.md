
# Development
## Setup
1. This project uses [just](https://github.com/casey/just) to run commands.
If you don't want to use it, you can execute the commands in `justfile` manually.

1. This project uses [poetry](https://python-poetry.org/) for dependencies management.

1. This project interfaces with [docker](https://www.docker.com/).
You should install it.
Right now, for ease of development, your current user should be part of the docker group
   ([link](https://docs.docker.com/engine/install/linux-postinstall/)).
This is a security concern.

1. `just setup-dev`

## Run
1. Run `just dev-start` at the beginning of your development session to start docker containers.
1. Modify code, then run `just run-dl2ac-dev-local-once`.
1. Run `just dev-stop` at the end of your development session to stop docker containers.
