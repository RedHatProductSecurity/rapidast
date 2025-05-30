import logging

from configmodel.models.general import ContainerType
from configmodel.models.scanners.generic import GenericConfig
from configmodel.models.scanners.generic import GenericContainer
from configmodel.models.scanners.generic import GenericContainerParameters


class TestGenericContainerParameters:
    def test_initialization_with_values(self):
        params = GenericContainerParameters(
            image="my-image", command="run.sh", validReturns=[0, 1], podName="my-pod", volumes=["/data:/app_data"]
        )
        assert params.image == "my-image"
        assert params.command == "run.sh"
        assert params.validReturns == [0, 1]
        assert params.podName == "my-pod"
        assert params.volumes == ["/data:/app_data"]


class TestGenericConfig:
    def test_invalid_config_both_missing_logs_error(self, caplog):
        with caplog.at_level(logging.ERROR):
            config = GenericConfig()
            assert config.inline is None
            assert config.container is None

            assert len(caplog.records) == 1
            assert caplog.records[0].levelname == "ERROR"

    def test_invalid_config_both_present_raises_value_error(self, caplog):
        with caplog.at_level(logging.ERROR):
            container_params = GenericContainerParameters(image="my-scanner-image")

            container = GenericContainer(parameters=container_params)
            GenericConfig(inline="print('hello')", container=container)

            assert len(caplog.records) == 1
            assert caplog.records[0].levelname == "ERROR"
