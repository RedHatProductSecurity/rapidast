from collections import namedtuple
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from scanners import downloaders


@pytest.fixture(scope="function")
def my_auth():
    return {
        "url": "auth_url",
        "client_id": "auth_client_id",
        "rtoken": "aut_rtoken",
    }


@pytest.fixture(scope="function")
def my_proxy():
    proxy = {
        "proxyHost": "proxyHost",
        "proxyPort": "proxyPort",
    }


@patch("scanners.downloaders.requests.get")
def test_anonymous_download(mock_get, my_proxy):
    def request_get(url, allow_redirects=True, proxies=None, verify=True):
        Response = namedtuple("Response", ["status_code", "content"])
        return Response(status_code=200, content="content")

    mock_get.side_effect = request_get

    ret = downloaders.anonymous_download("url", dest=None, proxy=my_proxy)

    assert ret == "content"


@patch("scanners.downloaders.requests.Session")
def test_oauth2_get_token_from_rtoken(mock_session, my_auth, my_proxy):
    class fake_Session:
        def post(self, url, **kwargs):
            Post = namedtuple("Post", ["raise_for_status", "text"])
            return Post(raise_for_status=lambda: None, text=b"{'access_token':123}")

    mock_session.side_effect = fake_Session

    rtoken = downloaders.oauth2_get_token_from_rtoken(auth=my_auth, proxy=my_proxy, session=None)

    assert rtoken == 123


@patch("scanners.downloaders.requests.Session")
@patch("scanners.downloaders.oauth2_get_token_from_rtoken")
@patch("builtins.open")
def test_authenticated_download_with_rtoken(mock_open, mock_get_rtoken, mock_session, my_auth, my_proxy):
    class fake_Session:
        def post(self, url, **kwargs):
            Post = namedtuple("Post", ["raise_for_status", "text"])
            return Post(raise_for_status=lambda: None, text=b"{'access_token':123}")

        def get(self, url, **kwargs):
            Get = namedtuple("Get", ["status_code", "text"])
            return Get(status_code=200, text="text")

    mock_session.side_effect = fake_Session
    mock_get_rtoken.return_value = "123"
    mock_open.return_value = MagicMock()

    res = downloaders.authenticated_download_with_rtoken("url", "Nowhere", auth=my_auth, proxy=my_proxy)
    assert res == True
