from dataclasses import dataclass, field
from typing import Optional, List, Any, Dict
from enum import Enum

class ContainerType(str, Enum):
    PODMAN = "podman"
    NONE = "none"

class AuthenticationType(str, Enum):
    OAUTH2_RTOKEN = "oauth2_rtoken"
    HTTP_BASIC = "http_basic"
    HTTP_HEADER = "http_header"
    COOKIE = "cookie"
    BROWSER = "browser"

@dataclass
class Oauth2RtokenParameters:
    rtoken: str
    client_id: str
    token_endpoint: str
    preauth: Optional[str] = None

@dataclass
class HttpBasicParameters:
    username: str
    password: str

@dataclass
class HttpHeaderParameters:
    value: str
    name: str = "Authorization"

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
    loginPageWait: Optional[str] = None
    loggedInRegex: Optional[str] = None
    loggedOutRegex: Optional[str] = None

@dataclass
class Proxy:
    proxyHost: str
    proxyPort: str # @FIX: This should be an integer, but it is referenced as a string in the templates

@dataclass
class Authentication:
    type: AuthenticationType
    parameters: Any # @FIX: improve this

@dataclass
class ContainerParameters:
    validReturns: Optional[List[int]] = field(default_factory=list)
    image: Optional[str] = None
    executable: Optional[str] = None
    podName: Optional[str] = None
    volumes: Optional[List[int]] = field(default_factory=list)

@dataclass
class Container:
    type: ContainerType = ContainerType.NONE
    parameters: Optional[ContainerParameters] = None

@dataclass
class DefectDojoExport:
    parameters: Optional[Dict[str, Any]] = field(default_factory=dict)

@dataclass
class General:
    proxy: Optional[Proxy] = None
    authentication: Optional[Authentication] = None
    container: Optional[Container] = None
    defectDojoExport: Optional[DefectDojoExport] = None
