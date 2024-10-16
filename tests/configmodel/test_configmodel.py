import copy
import os
import unittest
from unittest.mock import mock_open
from unittest.mock import patch

import pytest
import yaml

from configmodel import RapidastConfigModel


@pytest.fixture(name="config_template")
def generate_config_template():
    model = "config/config-template-zap-long.yaml"
    try:
        with open(model) as file:
            config = RapidastConfigModel(yaml.safe_load(file))
    except yaml.YAMLError as exc:
        raise RuntimeError("Unable to load TEST file {model}") from exc

    return config


@pytest.fixture(name="some_nested_config")
def generate_some_nested_config():
    return {
        "key1": "value1",
        "key2": {"key21": "value21"},
        "key3": "value3",
        "key4": "value4",
        "nested": {"morenested": {"key3": "nestedvalue"}},
        "nothing": None,
        "falsekey": False,
    }


@pytest.fixture(name="nested_with_var")
def generate_some_nested_config_with_var():
    os.environ["SECRETKEY"] = "ABC"
    return {
        "key1": "value1",
        "key2": {"key21": "value21"},
        "key3": "value3",
        "key4": "value4",
        "nested": {
            "morenested": {
                "key3": "nestedvalue",
                "secretkey_from_var": "SECRETKEY",
                "nestnest": {"leaf": "value"},
            },
            "list": [1, 2, 3, {"foo_from_var": "SECRETKEY"}, 4, 5],
        },
        "nothing": None,
        "falsekey": False,
    }


def test_subtree_to_dict(nested_with_var):
    myconf = RapidastConfigModel(nested_with_var)

    # make a "backup" of the original config, to look for unexpected modification
    original = copy.deepcopy(myconf.conf)

    d = myconf.subtree_to_dict("nested.morenested")
    expected = {
        "key3": "nestedvalue",
        "secretkey": "ABC",
        "nestnest": {"leaf": "value"},
    }
    assert d == expected
    # also verify that the original config dictionary was not modified
    assert original == myconf.conf

    # same test, one layer up
    d = myconf.subtree_to_dict("nested")
    expected = {
        "morenested": {
            "key3": "nestedvalue",
            "secretkey": "ABC",
            "nestnest": {"leaf": "value"},
        },
        "list": [1, 2, 3, {"foo": "ABC"}, 4, 5],
    }
    assert d == expected
    # also verify that the original config dictionary was not modified
    assert original == myconf.conf

    # pointing to a non-dictionary generates a KeyError
    with pytest.raises(KeyError):
        myconf.subtree_to_dict("key1")

    # pointing to a non existing entry return an empty dict
    d = myconf.subtree_to_dict("nested.foo")
    assert d == None


def test_configmodel_exists(some_nested_config):
    myconf = RapidastConfigModel(some_nested_config)

    # verify that some values exist
    assert myconf.exists("key1")
    assert myconf.exists("nested.morenested.key3")
    assert myconf.exists("nothing")

    # verify that some values do not exist
    assert not myconf.exists("thisdoesntexists")
    assert not myconf.exists("key1.thisdoesntexists")
    assert not myconf.exists("key1.value1.thisdoesntexists")
    assert not myconf.exists("key1.value2.thisdoesntexists")
    assert not myconf.exists("nested.value2.thisdoesntexists")
    assert not myconf.exists("nothing.thisdoesntexists")

    # exists looks for keys, not values, so these should return False also
    assert not myconf.exists("key1.value1")
    assert not myconf.exists("nested.morenested.key3.nestedvalue")


def test_configmodel_get(some_nested_config):
    myconf = RapidastConfigModel(some_nested_config)

    # existing get
    assert myconf.get("key1", "x") == "value1"
    assert myconf.get("nested.morenested", "x") == {"key3": "nestedvalue"}

    # unexisting values
    assert myconf.get("thisdoesnotexists", "x") == "x"
    assert myconf.get("nested.thisdoesnotexists", "x") == "x"

    # Value from config "_from_var"
    os.environ["MY_SECRET"] = "myEnvVal"
    myconf.set("nested.keyenv.def_from_var", "MY_SECRET")
    assert myconf.get("nested.keyenv.def", "x") == os.environ["MY_SECRET"]


def test_configmodel_set(some_nested_config):
    myconf = RapidastConfigModel(some_nested_config)

    # Simple set *but* no overwrite (no change)
    myconf.set("key2.key21", "mynewval", overwrite=False)
    assert myconf.get("key2.key21") == "value21"

    # Simple set with overwrite (successful overwrite)
    myconf.set("key2.key21", "mynewval", overwrite=True)
    assert myconf.get("key2.key21") == "mynewval"

    # incompatible set, no overwrite
    myconf.set("nested.morenested", "mynewval", overwrite=False)
    assert myconf.get("nested.morenested.key3") == "nestedvalue"

    # incompatible set, with overwrite
    myconf.set("nested.morenested", "mynewval", overwrite=True)
    assert myconf.get("nested.morenested") == "mynewval"

    # deep sets
    # `set` should rewrite a `None` value even on `overwrite=False`
    myconf.set("nothing.some.more.nested", "newval", overwrite=False)
    assert myconf.get("nothing.some.more.nested") == "newval"
    # but should not rewrite a value set to False value
    myconf.set("falsekey.some.more.nested", "newval", overwrite=False)
    assert not myconf.exists("falsekey.some.more.nested")
    # unless we overwrite
    myconf.set("falsekey.some.more.nested", "newval", overwrite=True)
    assert myconf.exists("falsekey.some.more.nested")
    assert myconf.get("falsekey.some.more.nested") == "newval"


def test_configmodel_move(some_nested_config):
    myconf = RapidastConfigModel(some_nested_config)

    # Simple move
    myconf.move("key1", "moved_key1")
    assert myconf.get("moved_key1", "x") == "value1"
    assert not myconf.exists("key1")

    # moving into a sub-entry is supposed to fail
    # also verify that the move failed and that the config did not get modified
    with pytest.raises(ValueError):
        myconf.move("key2", "key2.new_destination")
    assert myconf.get("key2", "x") == {"key21": "value21"}

    # moving a whole dictionary
    myconf.move("nested", "key2.nested_moved")
    assert myconf.get("key2.nested_moved") == {"morenested": {"key3": "nestedvalue"}}
    assert not myconf.exists("nested")

    # Moving an unexisting entry should be silently ignored
    myconf.move("key2.doesnotexist", "key2.doesnotexist_moved")
    assert not myconf.exists("key2.doesnotexist")
    assert not myconf.exists("key2.doesnotexist_moved")

    # Moving should overwrite existing destination
    myconf.move("key3", "key4")
    assert not myconf.exists("key3")
    assert myconf.get("key4", "x") == "value3"


def test_configmodel_delete(some_nested_config):
    myconf = RapidastConfigModel(some_nested_config)

    # Simple delete
    myconf.delete("key1")
    assert not myconf.exists("key1")
    # Simple nested delete
    myconf.delete("key2.key21")
    assert myconf.exists("key2")
    assert not myconf.exists("key2.key21")
    # branch delete
    myconf.delete("nested")
    assert not myconf.exists("nested.morenested.key3")
    assert not myconf.exists("nested.morenested")
    assert not myconf.exists("nested")


@patch("builtins.open", new_callable=mock_open)
@patch("yaml.dump")
def test_dump_config(mock_yaml_dump, mock_file):
    config = RapidastConfigModel()

    config._dump_config("test-config.yaml", {"key": "value"})
    mock_file.assert_called_once_with("test-config.yaml", "w+", encoding="utf-8")
    mock_yaml_dump.assert_called_once_with({"key": "value"}, mock_file(), allow_unicode=True)


@patch("os.makedirs")
def test_dump(mock_os_makedirs, config_template):
    config = RapidastConfigModel(config_template)

    config_dir = "/path/to/dir"

    with patch.object(config, "_dump_config") as mock_dump_config:
        config.dump(config_dir)
        mock_os_makedirs.assert_called_once_with(config_dir, exist_ok=True)

        mock_dump_config.assert_any_call(f"{config_dir}/rendered-configuration.yaml", config_template)
        mock_dump_config.assert_any_call(f"{config_dir}/default-configuration.yaml", {})
        mock_dump_config.assert_any_call(f"{config_dir}/env-configuration.yaml", {})


@patch.dict(os.environ, {"SECRETKEY": "foo"})
def test_get_with_env_var(nested_with_var):
    config = RapidastConfigModel(nested_with_var)
    _ = config.get("nested.morenested.secretkey")
    assert config._env_conf["nested"]["morenested"]["secretkey"] == "foo"


def test_get_with_default(nested_with_var):
    config = RapidastConfigModel(nested_with_var)
    _ = config.get("non.existent.path", default="default_value")
    _ = config.get("another.existent.path", default="another_default_value")
    assert config._default_conf["non"]["existent"]["path"] == "default_value"
    assert config._default_conf["another"]["existent"]["path"] == "another_default_value"
