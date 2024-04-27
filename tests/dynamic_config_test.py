import dataclasses
from pathlib import Path

from hypothesis import given, strategies as st

from dl2ac import config


authelia_policy_strategy = st.sampled_from(config.AutheliaPolicy)
runtime_environment_cli_strategy = st.sampled_from(config.RuntimeEnvironmentCli)
path_strategy = st.builds(Path, st.text())
dynamic_config_overrides_strategy = st.builds(
    config.DynamicConfigOverrides,
    default_authelia_policy=authelia_policy_strategy | st.none(),
    default_rule_policy=authelia_policy_strategy | st.none(),
    environment=runtime_environment_cli_strategy | st.none(),
    authelia_config_file=path_strategy | st.none(),
    rules_file=path_strategy | st.none(),
    sleep_at_start_n_seconds=st.integers(min_value=0),
    sleep_interval_n_seconds=st.integers(min_value=0),
    source_description=st.text(),
)
dynamic_config_strategy = st.builds(
    config.DynamicConfig,
    default_authelia_policy=authelia_policy_strategy,
    default_rule_policy=authelia_policy_strategy,
    environment=runtime_environment_cli_strategy,
    authelia_config_file=path_strategy,
    rules_file=path_strategy,
    sleep_at_start_n_seconds=st.integers(min_value=0),
    sleep_interval_n_seconds=st.integers(min_value=0),
)


@given(
    dynamic_config_strategy,
    dynamic_config_strategy,
    st.lists(dynamic_config_overrides_strategy),
)
def test_any_config(
    expected_dynamic_config: config.DynamicConfig,
    defaults: config.DynamicConfig,
    overrides: list[config.DynamicConfigOverrides],
) -> None:
    # Dynamic config will load the first non-None value for a given field.
    # So, let's generate input data that should generate expected_dynamic_config.
    for field in dataclasses.fields(config.DynamicConfig):
        has_set = False
        for override in overrides:
            if getattr(override, field.name) is None:
                continue

            # Set the first non-None value to the expected value.
            setattr(override, field.name, getattr(expected_dynamic_config, field.name))
            has_set = True
            break

        if has_set:
            continue

        # If there's no non-None value for that field in overrides (perhaps list is empty)
        # then set it on the defaults object
        setattr(defaults, field.name, getattr(expected_dynamic_config, field.name))

    actual_dynamic_config = config.DynamicConfig.load(defaults, overrides)
    assert actual_dynamic_config == expected_dynamic_config


@given(
    dynamic_config_strategy,
    dynamic_config_strategy,
    st.lists(dynamic_config_overrides_strategy, max_size=3),
)
def test_first_config(
    expected_dynamic_config: config.DynamicConfig,
    defaults: config.DynamicConfig,
    overrides: list[config.DynamicConfigOverrides],
) -> None:
    kwargs = {
        field.name: expected_dynamic_config.__dict__[field.name]
        for field in dataclasses.fields(config.DynamicConfig)
    }
    expected_overrides = config.DynamicConfigOverrides(
        source_description='expected', **kwargs
    )
    overrides = [expected_overrides] + overrides
    actual_dynamic_config = config.DynamicConfig.load(defaults, overrides)
    assert actual_dynamic_config == expected_dynamic_config
