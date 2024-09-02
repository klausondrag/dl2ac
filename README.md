
[!WARNING] This project is under active development and not ready for usage in production.

# Introduction
This project brings configuration via docker labels à la
traefik to [authelia](https://www.authelia.com/).
dl2ac runs in a docker container and monitors docker labels.
When detecting a change, it will update the authelia config and restart the authelia docker container.
It will convert docker labels like this:
```yaml
  labels:
    dl2ac.rules.one.domain.1: '*.example.com'
    dl2ac.rules.one.policy: one_factor
    dl2ac.rules.one.rank: 10
```

into this:
```yaml
default_policy: deny
rules:
- domain:
  - '*.example.com'
  policy: one_factor
```

# Running
Here's an example [docker compose file](./example/compose.yaml).
You also need a configuration and users_database, which can also be found in the [example](./example) folder.
```bash
git clone git@github.com:klausondrag/dl2ac.git --depth 1
cd dl2ac/example
sudo docker compose up
```
Navigate to [https://hello.home.localhost/](https://hello.home.localhost/) in your browser.
Accept the self-signed certificates.
You should be prompted to authenticate.
Use `authelia` as username and password to login.
Now the hello service is behind an auth server, configured by docker labels!

Navigate to [https://login.home.localhost/](https://login.home.localhost/) and sign out.
Navigate to [https://hello.home.localhost/](https://hello.home.localhost/) again and see that you're required to login again.


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
