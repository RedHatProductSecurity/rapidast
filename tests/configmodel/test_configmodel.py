import os

import pytest
import yaml

from configmodel import RapidastConfigModel


@pytest.fixture(name="config_template")
def generate_config_template():
    model = "config/config-template-long.yaml"
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
    }


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
