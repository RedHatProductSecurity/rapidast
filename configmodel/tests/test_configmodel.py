import yaml

import pytest
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
        "nested": {"morenested": {"key3": "nestedvalue"}},
    }


def test_configmodel_get(some_nested_config):
    myconf = RapidastConfigModel(some_nested_config)

    # existing get
    assert myconf.get("key1", "x") == "value1"
    assert myconf.get("nested.morenested", "x") == {"key3": "nestedvalue"}

    # unexisting values
    assert myconf.get("nothing", "x") == "x"
    assert myconf.get("nested.nothing", "x") == "x"


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
