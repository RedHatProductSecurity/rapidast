import pytest

import configmodel


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel({"application": {"url": "http://example.com"}, "scanners": {"zap": {}}})
