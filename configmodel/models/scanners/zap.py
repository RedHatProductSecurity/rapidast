# pylint: disable=invalid-name
import logging
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Union


class ImportUrlsFromFileType(str, Enum):
    HAR = "har"
    MODSEC2 = "modsec2"
    URL = "url"
    ZAP_MESSAGES = "zap_messages"


@dataclass
class ZapApis:
    apiUrl: Optional[str] = None
    apiFile: Optional[str] = None

    def __post_init__(self):
        has_url = self.apiUrl is not None and self.apiUrl != ""
        has_file = self.apiFile is not None and self.apiFile != ""

        if not (has_url or has_file):
            raise ValueError("No apiUrl or apiFile is defined in the config, in apiScan.apis")


@dataclass
class ZapApiScan:
    apis: ZapApis


@dataclass
class ZapImportUrlsFromFile:
    fileName: str
    type: ImportUrlsFromFileType = ImportUrlsFromFileType.URL


@dataclass
class ZapGraphql:
    endpoint: Optional[str] = None
    schemaUrl: Optional[str] = None
    schemaFile: Optional[str] = None


@dataclass
class ZapSpider:
    pass


@dataclass
class ZapSpiderAjax:
    maxDuration: Optional[int] = None
    url: Optional[str] = None
    browserId: Optional[str] = None
    maxCrawlState: Optional[int] = None


@dataclass
class ReplacerRule:
    description: Optional[str] = None
    url: Optional[str] = None
    matchType: Optional[str] = None
    matchString: Optional[str] = None
    matchRegex: Optional[bool] = None
    replacementString: Optional[str] = None
    tokenProcessing: Optional[bool] = None


@dataclass
class ReplacerParameters:
    deleteAllRules: Optional[bool] = True


@dataclass
class ZapReplacer:
    rules: List[ReplacerRule] = field(default_factory=list)
    parameters: Optional[ReplacerParameters] = field(default_factory=ReplacerParameters)

    def __post_init__(self):
        if not self.rules:
            raise ValueError("replacer must have a rule at least")

    def to_rules_dict_list(self) -> List[Dict[str, Any]]:
        """
        Converts the list of ReplacerRule objects into a list of dictionaries,
        excluding keys with None values. This format is required by the ZAP
        automation framework for replacer rules
        """
        result_list = []
        for rule_obj in self.rules:
            rule_dict = asdict(rule_obj)
            # Filter out keys where the value is None
            filtered_dict = {k: v for k, v in rule_dict.items() if v is not None}
            result_list.append(filtered_dict)
        return result_list


@dataclass
class ZapPassiveScan:
    disabledRules: Optional[str] = None


@dataclass
class ZapActiveScan:
    policy: Optional[str] = None
    maxRuleDurationInMins: Optional[int] = None


@dataclass
class ZapMiscOptions:
    overrideConfigs: Optional[List[str]] = field(default_factory=list)
    memMaxHeap: Optional[str] = None
    updateAddons: Optional[bool] = None
    additionalAddons: Optional[str] = None


@dataclass
class ZapReport:
    format: Optional[Union[list[str], str]] = field(default_factory=list)


@dataclass
class ZapUrls:
    includes: Optional[List[str]] = field(default_factory=list)
    excludes: Optional[List[str]] = field(default_factory=list)


@dataclass
class ZapConfig:  # pylint: disable=R0902
    apiScan: Optional[ZapApiScan] = None
    importUrlsFromFile: Optional[ZapImportUrlsFromFile] = None
    graphql: Optional[ZapGraphql] = None
    spider: Optional[ZapSpider] = None
    spiderAjax: Optional[ZapSpiderAjax] = None
    replacer: Optional[ZapReplacer] = None
    passiveScan: Optional[ZapPassiveScan] = None
    activeScan: Optional[ZapActiveScan] = None
    miscOptions: Optional[ZapMiscOptions] = None
    report: Optional[ZapReport] = None
    urls: Optional[ZapUrls] = None

    def __post_init__(self):
        required_flags = ["apiScan", "importUrlsFromFile", "graphql", "spider", "spiderAjax"]
        if not any(getattr(self, flag) for flag in required_flags):
            error_msg = "ZAP Scanner requires at least one of the following to be enabled: " + ", ".join(
                f"'{flag}'" for flag in required_flags
            )
            # @TODO: Consider raising an exception here
            # However, to maintain backward compatibility, we currently log an error instead
            logging.error(error_msg)
