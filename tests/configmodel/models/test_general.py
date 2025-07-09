import pytest
from dacite import Config
from dacite import from_dict

from configmodel.models.general import Authentication
from configmodel.models.general import AuthenticationType
from configmodel.models.general import BrowserParameters
from configmodel.models.general import CookieParameters
from configmodel.models.general import HttpBasicParameters
from configmodel.models.general import HttpHeaderParameters
from configmodel.models.general import OAuth2RTokenParameters

dacite_config = Config(
    # strict=True,
    type_hooks={
        # Dacite doesn't natively support enums, so we use `type_hooks` as a workaround
        # to properly resolve enum values
        # https://github.com/konradhalas/dacite/issues/61
        AuthenticationType: AuthenticationType
    },
)


@pytest.mark.parametrize(
    "cls, data",
    [
        (
            OAuth2RTokenParameters,
            {"client_id": "client", "token_endpoint": "https://token.url", "rtoken": "RTOKEN", "preauth": True},
        ),
        (HttpHeaderParameters, {"name": "Authorization", "value": "Bearer abc"}),
        (HttpBasicParameters, {"username": "user", "password": "pass"}),
        (CookieParameters, {"name": "session", "value": "abc123"}),
        (
            BrowserParameters,
            {
                "username": "user",
                "password": "pass",
                "loginPageUrl": "https://login.url",
                "verifyUrl": "https://verify.url",
                "loginPageWait": 2,
                "loggedInRegex": "200 OK",
                "loggedOutRegex": "403 Forbidden",
            },
        ),
    ],
)
def test_auth_parameter_dataclasses(cls, data):
    """
    Validate that all supported parameter dataclasses correctly accept and store input values.
    """
    obj = from_dict(data_class=cls, data=data)
    for k, v in data.items():
        assert getattr(obj, k) == v


@pytest.mark.parametrize(
    "auth_type, params_class, params_dict",
    [
        (
            "oauth2_rtoken",
            OAuth2RTokenParameters,
            {"client_id": "abc", "token_endpoint": "https://example.com/token", "rtoken": "RTOKEN", "preauth": False},
        ),
        ("http_header", HttpHeaderParameters, {"name": "Authorization", "value": "Bearer token"}),
        ("http_basic", HttpBasicParameters, {"username": "admin", "password": "secret"}),
        ("cookie", CookieParameters, {"name": "sessionid", "value": "xyz"}),
        (
            "browser",
            BrowserParameters,
            {
                "username": "user",
                "password": "pass",
                "loginPageUrl": "https://login.page",
                "verifyUrl": "https://verify.page",
                "loginPageWait": 2,
                "loggedInRegex": "200 OK",
                "loggedOutRegex": "403 Forbidden",
            },
        ),
    ],
)
def test_authentication_deserialization(auth_type, params_class, params_dict):
    """
    Test that Authentication parses its `parameters` field into the correct subclass
    based on the declared `type`.
    """
    raw_data = {"type": auth_type, "parameters": params_dict}

    auth = from_dict(data_class=Authentication, data=raw_data, config=dacite_config)
    assert auth.type == auth_type
    assert isinstance(auth.parameters, params_class)

    for key, value in params_dict.items():
        assert getattr(auth.parameters, key) == value


def test_authentication_unknown_type_raises():
    """
    Ensure that if an unsupported authentication type is passed, a ValueError is raised.
    """
    raw_data = {"type": "invalid_auth_type", "parameters": {}}

    with pytest.raises(ValueError):
        from_dict(data_class=Authentication, data=raw_data, config=dacite_config)


def test_authentication_wrong_parameters_type():
    """
    Ensure that a non-dict parameters input raises a TypeError
    (since parameters must be a dictionary).
    """
    raw_data = {"type": "http_basic", "parameters": "this should be a dict"}

    with pytest.raises(TypeError):
        from_dict(data_class=Authentication, data=raw_data, config=dacite_config)
