FROM python:3.12.2-slim as python-base

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_DEFAULT_TIMEOUT=100
# https://python-poetry.org/docs#ci-recommendations
ENV POETRY_VERSION=1.8.2
# ENV POETRY_HOME=/opt/poetry/data
# ENV POETRY_VIRTUALENVS_PATH=/opt/poetry/venv
# ENV POETRY_CACHE_DIR=/opt/poetry/.cache
# ENV POETRY_VIRTUALENVS_IN_PROJECT=1
ENV POETRY_VIRTUALENVS_CREATE=false

RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}"

WORKDIR /app
COPY ./pyproject.toml ./poetry.lock ./
RUN poetry install --no-interaction --no-cache

# FROM python:3.12.2-slim
# WORKDIR /app
# COPY --from=python-base /app /app
# RUN source .venv/bin/activate
COPY . .
CMD ["python3", "cli.py", "dl2ac", "run-loop"]
