# pylint: disable=C0103
from dataclasses import dataclass
from typing import Optional
from typing import Union


@dataclass
class Environ:
    envFile: str


@dataclass
class GoogleCloudStorage:
    keyFile: Optional[str] = None
    bucketName: str = ""
    directory: Optional[str] = None


@dataclass
class DefectDojoAuthorization:
    username: str
    password: str
    token: str


@dataclass
class DefectDojo:
    url: str
    authorization: Optional[DefectDojoAuthorization]
    ssl: bool = True


@dataclass
class Config:
    configVersion: int
    base_results_dir: str = "./results"
    tls_verify_for_rapidast_downloads: Union[bool, str] = True

    environ: Optional[Environ] = None
    googleCloudStorage: Optional[GoogleCloudStorage] = None
    defectDojo: Optional[DefectDojo] = None
