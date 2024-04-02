from hypothesis import given
from hypothesis.strategies import text

from python_template import example


def test_example():
    assert True


@given(text())
def test_decode_inverts_encode(s):
    assert example.decode(example.encode(s)) == s
