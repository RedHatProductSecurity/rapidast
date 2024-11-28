from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests

import configmodel
import rapidast
from scanners.nessus.nessus_none import Nessus


class TestNessus:
    @patch("py_nessus_pro.PyNessusPro._authenticate")
    @patch("requests.Session.request")
    def test_setup_nessus(self, mock_get, auth):
        # All this mocking is for PyNessusPro.__init__() which attempts to connect to Nessus
        mock_get.return_value = Mock(spec=requests.Response)
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = '{"token": "foo", "folders": []}'

        config_data = rapidast.load_config("config/config-template-nessus.yaml")
        config = configmodel.RapidastConfigModel(config_data)
        test_nessus = Nessus(config=config)
        assert test_nessus is not None
        assert test_nessus.nessus_client is not None

    @patch("py_nessus_pro.PyNessusPro._authenticate")
    @patch("requests.Session.request")
    def test_setup_nessus_auth(self, mock_get, auth):
        # All this mocking is for PyNessusPro.__init__() which attempts to connect to Nessus
        mock_get.return_value = Mock(spec=requests.Response)
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = '{"token": "foo", "folders": []}'

        config_data = rapidast.load_config("config/config-template-nessus.yaml")
        config = configmodel.RapidastConfigModel(config_data)

        authentication = {"type": "invalid", "parameters": {"name": "Authorizaiton", "value": "123"}}
        config.set("scanners.nessus.authentication", authentication)

        with pytest.raises(RuntimeError, match="The authentication option is not supported"):
            test_nessus = Nessus(config=config)
