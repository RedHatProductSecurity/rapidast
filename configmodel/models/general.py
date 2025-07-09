# pylint: disable=C0103
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from typing import Any
from typing import Optional

from dacite import from_dict


class ContainerType(str, Enum):
    PODMAN = "podman"
    NONE = "none"


class AuthenticationType(str, Enum):
    OAUTH2_RTOKEN = "oauth2_rtoken"
    HTTP_HEADER = "http_header"
    HTTP_BASIC = "http_basic"
    COOKIE = "cookie"
    BROWSER = "browser"


@dataclass
class Proxy:
    proxyHost: str
    proxyPort: str


@dataclass
class OAuth2RTokenParameters:
    client_id: str
    token_endpoint: str
    rtoken: str
    preauth: Optional[bool] = None


@dataclass
class HttpHeaderParameters:
    value: str
    name: str = "Authorization"


@dataclass
class HttpBasicParameters:
    username: str
    password: str


@dataclass
class CookieParameters:
    name: str
    value: str


@dataclass
class BrowserParameters:
    username: str
    password: str
    loginPageUrl: str
    verifyUrl: str
    loginPageWait: Optional[int] = None
    loggedInRegex: Optional[str] = None
    loggedOutRegex: Optional[str] = None


auth_param_classes = {
    "oauth2_rtoken": OAuth2RTokenParameters,
    "http_header": HttpHeaderParameters,
    "http_basic": HttpBasicParameters,
    "cookie": CookieParameters,
    "browser": BrowserParameters,
}


@dataclass
class Authentication:
    type: AuthenticationType
    parameters: Any = field(repr=False)  # start as raw dict

    def __post_init__(self):
        param_cls = auth_param_classes.get(self.type)
        if param_cls is None:
            raise ValueError(f"Unknown authentication type: {self.type}")

        if isinstance(self.parameters, dict):
            self.parameters = from_dict(param_cls, self.parameters)
        elif not isinstance(self.parameters, param_cls):
            raise TypeError(f"parameters must be {param_cls} or dict, got {type(self.parameters)}")


@dataclass
class Container:
    type: ContainerType = ContainerType.PODMAN


@dataclass
class DefectDojoExportParameters:
    product_name: Optional[str] = None
    engagement_name: Optional[str] = None
    engagement: Optional[int] = None
    test_title: Optional[str] = None
    test: Optional[int] = None


@dataclass
class DefectDojoExport:
    parameters: DefectDojoExportParameters


@dataclass
class General:
    proxy: Optional[Proxy] = None
    authentication: Optional[Authentication] = None
    container: Optional[Container] = None
    defectDojoExport: Optional[DefectDojoExport] = None
