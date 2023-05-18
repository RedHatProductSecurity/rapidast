import pytest

from utils import safe_add


def test_no_operator():
    assert safe_add("1") == 1


def test_value_error():
    with pytest.raises(TypeError):
        safe_add("abc")


def test_addition():
    assert safe_add("2 + 3") == 5


def test_subtraction():
    assert safe_add("2 - 3") == -1


def test_negative():
    assert safe_add("-3") == -3


def test_positive():
    assert safe_add("+3") == 3


def test_mix():
    assert safe_add("+3+2-1") == 4
    assert safe_add("-3-2") == -5
    assert safe_add("3 + 2   - 1 - 4") == 0
