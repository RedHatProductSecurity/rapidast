import pytest

import configmodel
from scanners.generic.generic_podman import GenericPodman


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel()


## Basic test for generic ##


def test_generic_podman_cli(test_config):
    test_config.set("scanners.generic.container.parameters.image", "myimage")
    test_config.set("scanners.generic.container.parameters.podName", "myPod")

    scanner = GenericPodman(config=test_config)
    scanner.setup()
    assert {"podman", "run", "--name", "myimage", "--pod", "myPod"}.issubset(
        set(scanner.podman.get_complete_cli())
    )


def test_generic_podman_volume(test_config):
    test_config.set("scanners.generic.container.parameters.image", "myimage")
    test_config.set("scanners.generic.container.parameters.volumes", ["abc:def"])
    scanner = GenericPodman(config=test_config)
    scanner.setup()
    assert {"--volume", "abc:def"}.issubset(set(scanner.podman.get_complete_cli()))
