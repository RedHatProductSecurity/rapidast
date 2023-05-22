from pathlib import Path

import pytest

import configmodel.converter
from scanners.trivy.trivy_podman import TrivyPodman


@pytest.fixture(scope="function")
def test_config():
    new_config = configmodel.RapidastConfigModel()

    # this test file to test image scanning so we set the image name to have 'image' config
    new_config.set("scanners.trivy.image.name", "alpine:latest")
    return new_config


def test_trivy_setup_executable(test_config):
    test_config.set("scanners.trivy.container.parameters.executable", "trivy")

    test_trivy = TrivyPodman(config=test_config)
    test_trivy.setup()

    assert test_trivy.trivy_cli[0] == "trivy" and test_trivy.trivy_cli[1] == "image"


def test_trivy_setup_empty_executable(test_config):
    test_config.set("scanners.trivy.container.parameters.executable", "")

    test_trivy = TrivyPodman(config=test_config)
    test_trivy.setup()

    # when the container.parameters.executable is set to "", podman run a command like "image <image>", not "trivy image <image>"
    assert test_trivy.trivy_cli[0] == "image"


def test_trivy_setup_skip_dbupdate(test_config):
    test_config.set("scanners.trivy.miscOptions.skipDbUpdate", "true")

    test_trivy = TrivyPodman(config=test_config)
    test_trivy.setup()

    assert "--skip-db-update" in test_trivy.trivy_cli


def test_trivy_setup_severity(test_config):
    test_config.set("scanners.trivy.report.severity", "high,critical")

    test_trivy = TrivyPodman(config=test_config)
    test_trivy.setup()

    assert "--severity" in test_trivy.trivy_cli
    assert "high,critical" in test_trivy.trivy_cli


def test_trivy_setup_report_format(test_config):
    test_config.set("scanners.trivy.report.format", "sarif")

    test_trivy = TrivyPodman(config=test_config)
    test_trivy.setup()

    assert "--format=sarif" in test_trivy.trivy_cli
    assert (
        "--output=/trivy/results/reports/image-scan-sarif-result.json"
        in test_trivy.trivy_cli
    )


def test_trivy_setup_default_scanner(test_config):
    test_trivy = TrivyPodman(config=test_config)
    test_trivy.setup()

    assert "--scanners=vuln" in test_trivy.trivy_cli
