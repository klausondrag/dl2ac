from hypothesis import settings, Verbosity


# Some tests run occasionally slow on my laptop,
# so let's disable the deadline for tests
settings.register_profile('ci', max_examples=1_000)
settings.register_profile('dev-all', max_examples=100, deadline=None)
settings.register_profile('dev', max_examples=10, deadline=None)
settings.register_profile(
    'debug', max_examples=10, deadline=None, verbosity=Verbosity.verbose
)
