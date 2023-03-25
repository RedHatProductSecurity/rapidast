import glob
import logging
import os
import pprint
import shutil
import tarfile
import tempfile
from base64 import urlsafe_b64encode

import yaml

from scanners import generic_authentication_factory
from scanners import RapidastScanner
from scanners.path_translators import PathMaps


CLASSNAME = "Zap"


pp = pprint.PrettyPrinter(indent=4)

# Helper: absolute path to this directory (which is not the current directory)
# Useful for finding files in this directory
MODULE_DIR = os.path.dirname(__file__)


class Zap(RapidastScanner):
    ## CONSTANTS
    DEFAULT_CONTEXT = "Default Context"
    AF_TEMPLATE = "af-template.yaml"
    USER = "test1"
    ZAP_REPORT_TEMPLATE_HTML = "traditional-html-plus"
    ZAP_REPORT_TEMPLATE_JSON = "traditional-json-plus"
    ZAP_REPORT_TEMPLATE_SARIF = "sarif-json"

    DEFAULT_CONTAINER = "podman"
    DEFAULT_REPORT_NAME_PREFIX = "rapidast-report"

    ## FUNCTIONS
    def __init__(self, config):
        logging.debug("Initializing ZAP scanner")
        super().__init__(config)

        self.results_dir = os.path.join(
            self.config.get("config.results_dir", default="results"), "zap"
        )

        # This is used to construct the ZAP Automation config.
        # It will be saved to a file during setup phase
        # and used by the ZAP command during run phase
        self.af = {}

        # When state is READY, this will contain the entire ZAP command that the container layer should run
        self.zap_cli = []

        # Defines whether a User has been created
        self.authenticated = False

        # Instanciate a PathMaps with predifined mapping IDs. They will be filled by the typed scanners
        # List important locations for host <-> container mapping point
        # + work: where data is stored:
        #   - AF file, reports, evidence, etc. are beneath this path
        # + scripts: where scripts are stored
        # + policies: where policies are stored
        self.path_map = PathMaps("workdir", "policies", "scripts")

    ###############################################################
    # PUBLIC METHODS                                              #
    # Called via inheritence only                                 #
    ###############################################################

    def setup(self):
        """Prepares everything:
        - the command line to run
        - environment variables
        - files & directory

        This code handles only the "ZAP" layer, independently of the container used.
        This method should not be called directly, but only via super() from a child's setup()
        """
        logging.info("Preparing ZAP configuration")
        self._setup_zap_cli()
        self._setup_zap_automation()

    def run(self):
        """This code handles only the "ZAP" layer, independently of the container used.
        This method should not be called directly, but only via super() from a child's setup()
        This method is currently empty as running entirely depends on the containment
        """
        pass

    def postprocess(self):
        host_results = self.path_map.workdir.host_path

        logging.info(f"Extracting report, storing in {self.results_dir}")
        os.makedirs(self.results_dir, exist_ok=True)

        for report_item in glob.glob(
            os.path.join(host_results, Zap.DEFAULT_REPORT_NAME_PREFIX) + "*"
        ):
            logging.debug(f"shutil copying {report_item}")

            if os.path.isdir(report_item):
                shutil.copytree(
                    report_item, self.results_dir + "/" + report_item.split("/")[-1]
                )
            else:
                shutil.copy(report_item, self.results_dir)

        logging.info("Saving the session as evidence")
        with tarfile.open(f"{self.results_dir}/session.tar.gz", "w:gz") as tar:
            tar.add(host_results, arcname="evidences")

    def cleanup(self):
        """Generic ZAP cleanup: should be called only via super() inheritance"""
        pass

    ###############################################################
    # PROTECTED METHODS                                           #
    # Called via Zap or inheritence only                          #
    # May be overloaded by inheriting classes                     #
    ###############################################################

    def get_type(self):
        """Return container type, based on configuration.
        This is only a helper to shorten long lines
        """
        return self.config.get(
            "scanners.zap.container.type", default=Zap.DEFAULT_CONTAINER
        )

    def _add_env(self, key, value=None):
        logging.warning(
            "_add_env() was called on the parent ZAP class. This is likely a bug. No operation done"
        )

    def _create_work_dir(self):
        """This function simply creates a temporary directory aiming at storing data in transit.
        Data such as: the AF configuration, evidence, reports, etc.
        This directory will be deleted during cleanup.
        Descendent classes *may* overload this directory (e.g.: if they can't map /tmp)
        """
        temp_dir = tempfile.mkdtemp(prefix=f"rapidast_{self.__class__.__name__}_")
        logging.debug(f"Temporary work directory for ZAP scanner in host: {temp_dir}")
        return temp_dir

    def _host_work_dir(self):
        """Shortcut to the host path of the work directory"""
        return self.path_map.workdir.host_path

    def _container_work_dir(self):
        """Shortcut to the container path of the work directory"""
        return self.path_map.workdir.container_path

    def _include_file(self, host_path, dest_in_container=None):
        """Copies the file from host_path on the host to dest_in_container in the container
        Notes:
            - MUST be run after the mapping is done
            - If dest_in_container evaluates to False, default to `PathIds.WORK`
            - If dest_in_container is a directory, copy the file to it without renaming it
        """
        # 1. Compute host path
        if not dest_in_container:
            path_to_dest = self._host_work_dir()
        else:
            path_to_dest = self.path_map.container_2_host(dest_in_container)

        shutil.copy(host_path, path_to_dest)
        logging.debug(f"_include_file() '{host_path} → 'container:{path_to_dest}'")

    ###############################################################
    # PRIVATE METHODS                                             #
    # Those are called only from Zap itself                       #
    ###############################################################
    def _setup_zap_automation(self):
        # Load the Automation template
        try:
            af_template = f"{MODULE_DIR}/{Zap.AF_TEMPLATE}"
            logging.debug("Load the Automation Framework template")
            with open(af_template, "r") as stream:
                self.af = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            raise RuntimeError(
                f"Something went wrong while parsing the config '{af_template}':\n {str(exc)}"
            ) from exc

        # Configure the basic environment target
        try:
            af_context = find_context(self.af)
            af_context["urls"].append(self.config.get("application.url"))
        except KeyError as exc:
            raise RuntimeError(
                f"Something went wrong with the Zap scanner configuration, while creating the context':\n {str(exc)}"
            ) from exc

        # authentication MUST happen first in case a user is created
        self.authenticated = self.authentication_factory()

        # Create the AF configuration
        self._setup_spider()
        self._setup_ajax_spider()
        self._setup_api()
        self._setup_passive_scan()
        self._setup_active_scan()
        self._setup_passive_wait()
        self._setup_report()

        # The AF should now be setup and ready to be written
        self._save_automation_file()

    def _setup_api(self):
        """Prepare an openapi job and append it to the job list"""

        openapi = {"name": "openapi", "type": "openapi", "parameters": {}}
        api = self.config.get("scanners.zap.apiScan.apis", default={})
        if api.get("apiUrl"):
            openapi["parameters"]["apiUrl"] = api.get("apiUrl")
        elif api.get("apiFile"):
            # copy the file in the container's result directory
            # This allows the OpenAPI to be kept as evidence
            container_openapi_file = f"{self._container_work_dir()}/openapi.json"

            self._include_file(
                host_path=api.get("apiFile"), dest_in_container=container_openapi_file
            )
            openapi["parameters"]["apiFile"] = container_openapi_file
        else:
            logging.warning("No API defined in the config, in scanners.zap.apiScan.api")
        # default target: main URL, or can be overridden in apiScan
        openapi["parameters"]["targetUrl"] = self.config.get(
            "scanners.zap.apiScan.target", default=False
        ) or self.config.get("application.url")
        openapi["parameters"]["context"] = Zap.DEFAULT_CONTEXT

        self.af["jobs"].append(openapi)

    def _setup_spider(self):
        """Prepare an spider job and append it to the job list"""

        if self.config.get("scanners.zap.spider", default=False) is False:
            return

        af_spider = {
            "name": "spider",
            "type": "spider",
            "parameters": {
                "user": Zap.USER if self.authenticated else "",
                "maxDuration": self.config.get(
                    "scanners.zap.spider.maxDuration", default=0
                ),
                "url": self.config.get("scanners.zap.spider.url", default=""),
            },
        }

        # Add to includePath to the context
        if self.config.get("scanners.zap.spider.url"):
            new_include_path = self.config.get("scanners.zap.spider.url") + ".*"
            af_context = find_context(self.af)
            af_context["includePaths"].append(new_include_path)

        self.af["jobs"].append(af_spider)

    def _setup_ajax_spider(self):
        """Prepare an spiderAjax job and append it to the job list"""

        if self.config.get("scanners.zap.spiderAjax", default=False) is False:
            return

        af_spider_ajax = {
            "name": "spiderAjax",
            "type": "spiderAjax",
            "parameters": {
                "user": Zap.USER if self.authenticated else "",
                "maxDuration": self.config.get(
                    "scanners.zap.spiderAjax.maxDuration", default=0
                ),
                "url": self.config.get("scanners.zap.spiderAjax.url", default=""),
                "browserId": self.config.get(
                    "scanners.zap.spiderAjax.browserId", default="chrome-headless"
                ),
            },
        }

        # Add to includePath to the context
        if self.config.get("scanners.zap.spiderAjax.url"):
            new_include_path = self.config.get("scanners.zap.spiderAjax.url") + ".*"
            af_context = find_context(self.af)
            af_context["includePaths"].append(new_include_path)

        self.af["jobs"].append(af_spider_ajax)

    def _setup_passive_scan(self):
        """Adds the passive scan to the job list. Needs to be done prior to Active scan"""

        if self.config.get("scanners.zap.passiveScan", default=False) is False:
            return

        # passive AF schema
        passive = {
            "name": "passiveScan-config",
            "type": "passiveScan-config",
            "parameters": {
                "maxAlertsPerRule": 10,
                "scanOnlyInScope": True,
                "maxBodySizeInBytesToScan": 10000,
                "enableTags": False,
            },
            "rules": [],
        }

        # Fetch the list of disabled passive scan as scanners.zap.policy.disabledPassiveScan
        disabled = self.config.get("scanners.zap.passiveScan.disabledRules", default="")
        # ''.split('.') returns [''], which is a non-empty list (which would erroneously get into the loop later)
        disabled = disabled.split(",") if len(disabled) else []
        logging.debug(f"disabling the following passive scans: {disabled}")
        for rulenum in disabled:
            passive["rules"].append({"id": int(rulenum), "threshold": "off"})

        self.af["jobs"].append(passive)

    def _setup_passive_wait(self):
        """Adds a wait to the list of jobs, to make sure that the Passive Scan is finished"""

        if self.config.get("scanners.zap.passiveScan", default=False) is False:
            return

        # Available Parameters: maximum time to wait
        waitfor = {
            "type": "passiveScan-wait",
            "name": "passiveScan-wait",
            "parameters": {},
        }
        self.af["jobs"].append(waitfor)

    def _setup_active_scan(self):
        """Adds the active scan job list."""

        if self.config.get("scanners.zap.activeScan", default=False) is False:
            return

        active = {
            "name": "activeScan",
            "type": "activeScan",
            "parameters": {
                "context": Zap.DEFAULT_CONTEXT,
                "user": Zap.USER if self.authenticated else "",
                "policy": self.config.get(
                    "scanners.zap.activeScan.policy", default="API-scan-minimal"
                ),
            },
        }

        self.af["jobs"].append(active)

    def _construct_report_af(self, template, report_file):
        report_af = {
            "name": "report",
            "type": "report",
            "parameters": {
                "template": template,
                "reportDir": f"{self.path_map.workdir.container_path}/",
                "reportFile": report_file,
                "reportTitle": "ZAP Scanning Report",
                "reportDescription": "",
                "displayReport": False,
            },
        }

        return report_af

    def _setup_report(self):
        """Adds the report to the job list. This should be called last"""

        report_cfg = self.config.get("scanners.zap.report", default=False)

        is_report_format_set = False
        if report_cfg:
            logging.debug(
                f"report format configured: {report_cfg}, type: {type(report_cfg)}"
            )
            for report_format in report_cfg["format"]:
                logging.debug(f"report format configured: {report_format}")

                if report_format == "json":
                    zap_template = Zap.ZAP_REPORT_TEMPLATE_JSON
                    report_filename = self.DEFAULT_REPORT_NAME_PREFIX + ".json"
                elif report_format == "html":
                    zap_template = Zap.ZAP_REPORT_TEMPLATE_HTML
                    report_filename = self.DEFAULT_REPORT_NAME_PREFIX + ".html"
                elif report_format == "sarif":
                    zap_template = Zap.ZAP_REPORT_TEMPLATE_SARIF
                    report_filename = self.DEFAULT_REPORT_NAME_PREFIX + ".sarif.json"
                else:
                    logging.info(f"invalid report_format: {report_format}")
                    continue

                logging.debug(f"report filename: {report_filename}")
                is_report_format_set = True
                self.af["jobs"].append(
                    self._construct_report_af(zap_template, report_filename)
                )

        if not is_report_format_set:
            # default report format: json
            zap_template = "traditional-json-plus"
            report_filename = self.DEFAULT_REPORT_NAME_PREFIX + ".json"
            self.af["jobs"].append(
                self._construct_report_af(zap_template, report_filename)
            )

    def _setup_zap_cli(self):
        """prepare the zap command: self.zap_cli
        This is a list of strings, representing the entire ZAP command to match the desired run
        """

        self.zap_cli = [self.config.get("scanners.zap.container.parameters.executable")]

        # Proxy workaround (because it currently can't be configured from Automation Framework)
        proxy = self.config.get("scanners.zap.proxy")
        if proxy:
            self.zap_cli += [
                "-config",
                f"network.connection.httpProxy.host={proxy.get('proxyHost')}",
                "-config",
                f"network.connection.httpProxy.port={proxy.get('proxyPort')}",
                "-config",
                "network.connection.httpProxy.enabled=true",
            ]
        else:
            self.zap_cli += ["-config", "network.connection.httpProxy.enabled=false"]

        # Create a session, to store them as evidence
        self.zap_cli += [
            "-newsession",
            self.path_map.workdir.container_path + "/session_data/session",
            "-cmd",
            "-autorun",
            self.path_map.workdir.container_path + "/af.yaml",
        ]

        logging.debug(f"ZAP will run with: {self.zap_cli}")

    def _save_automation_file(self):
        """Save the Automation dictionary as YAML in the container"""
        af_host_path = self.path_map.workdir.host_path + "/af.yaml"
        with open(af_host_path, "w") as f:
            f.write(yaml.dump(self.af))
        logging.info(f"Saved Automation Framework in {af_host_path}")

    # Building an authentication factory for ZAP
    # For every authentication methods:
    # - Will extract authentication parameters from config's `scanners.zap.authentication.parameters`
    # - May modify `af` (e.g.: adding jobs, users)
    # - May add environment vars
    # - MUST return True if it created a user, and False otherwise
    @generic_authentication_factory("zap")
    def authentication_factory(self):
        """This is the default function, attached to error reporting"""
        raise RuntimeError(
            f"No valid authenticator found for ZAP. ZAP current config is: {self.config}"
        )

    @authentication_factory.register(None)
    def authentication_set_anonymous(self):
        """No authentication: don't do anything"""
        logging.info("ZAP NOT configured with any authentication")
        return False

    @authentication_factory.register("cookie")
    def authentication_set_cookie(self):
        """Configure authentication via HTTP Basic Authentication.
        Adds a 'Cookie: <name>=<value>' Header to every query

        Do this using the ZAP_AUTH_HEADER* environment vars

        Returns False as it does not create a ZAP user
        """
        params_path = "scanners.zap.authentication.parameters"
        cookie_name = self.config.get(f"{params_path}.name", None)
        cookie_val = self.config.get(f"{params_path}.value", None)

        self._add_env("ZAP_AUTH_HEADER", "Cookie")
        self._add_env("ZAP_AUTH_HEADER_VALUE", f"{cookie_name}={cookie_val}")

        logging.info("ZAP configured with Cookie authentication")
        return False

    @authentication_factory.register("http_basic")
    def authentication_set_http_basic_auth(self):
        """Configure authentication via HTTP Basic Authentication.
        Adds a 'Authorization: Basic <urlb64("{user}:{password}">' to every query

        Do this using the ZAP_AUTH_HEADER* environment vars

        Returns False as it does not create a ZAP user
        """
        params_path = "scanners.zap.authentication.parameters"
        username = self.config.get(f"{params_path}.username", None)
        password = self.config.get(f"{params_path}.password", None)

        blob = urlsafe_b64encode(f"{username}:{password}".encode()).decode("utf-8")

        self._add_env("ZAP_AUTH_HEADER", "Authorization")
        self._add_env("ZAP_AUTH_HEADER_VALUE", f"Basic {blob}")

        logging.info("ZAP configured with HTTP Basic Authentication")
        return False

    @authentication_factory.register("oauth2_rtoken")
    def authentication_set_oauth2_rtoken(self):
        """Configure authentication via OAuth2 Refresh Tokens
        In order to achieve that:
        - Create a ZAP user with username and refresh token
        - Sets the "script" authentication method in the ZAP Context
          - The script will request a new token when needed
        - Sets a "script" (httpsender) job, which will inject the latest
          token retrieved

        Returns True as it creates a ZAP user
        """

        context_ = find_context(self.af)
        params_path = "scanners.zap.authentication.parameters"
        client_id = self.config.get(f"{params_path}.client_id", "cloud-services")
        token_endpoint = self.config.get(f"{params_path}.token_endpoint", None)
        rtoken = self.config.get(f"{params_path}.rtoken_var_name", "RTOKEN")
        scripts_dir = self.path_map.scripts.container_path

        # 1- complete the context: script, verification and user
        context_["authentication"] = {
            "method": "script",
            "parameters": {
                "script": f"{scripts_dir}/offline-token.js",
                "scriptEngine": "ECMAScript : Oracle Nashorn",
                "client_id": client_id,
                "token_endpoint": token_endpoint,
            },
            "verification": {
                "method": "response",
                "loggedOutRegex": "\\Q401\\E",
                "pollFrequency": 60,
                "pollUnits": "requests",
                "pollUrl": "",
                "pollPostData": "",
            },
        }
        context_["users"] = [
            {
                "name": Zap.USER,
                "credentials": {"refresh_token": f"${{{rtoken}}}"},
            }
        ]
        # 2- add the name of the variable containing the token
        # The value will be taken from the environment at the time of starting
        self._add_env(rtoken)

        # 2- complete the HTTPSender script job
        script = {
            "name": "script",
            "type": "script",
            "parameters": {
                "action": "add",
                "type": "httpsender",
                "engine": "ECMAScript : Oracle Nashorn",
                "name": "add-bearer-token",
                "file": f"{scripts_dir}/add-bearer-token.js",
                "target": "",
            },
        }
        self.af["jobs"].append(script)
        logging.info("ZAP configured with OAuth2 RTOKEN")
        return True

    ###############################################################
    # MAGIC METHODS                                               #
    # Special functions (other than __init__())                   #
    ###############################################################


# Given an Automation Framework configuration, return its sub-dictionary corresponding to the context we're going to use
def find_context(af, context=Zap.DEFAULT_CONTEXT):
    # quick function that makes sure the context is sane
    def ensure_default(context2):
        # quick function that makes sure an entry is a list (override if necessary)
        def ensure_list(entry):
            if not context2.get(entry) or not isinstance(context2.get(entry), list):
                context2[entry] = []

        ensure_list("urls")
        ensure_list("includePaths")
        ensure_list("excludePaths")
        return context2

    try:
        for context3 in af["env"]["contexts"]:
            if context3["name"] == context:
                return ensure_default(context3)
    except:
        pass
    logging.warning(
        f"No context matching {context} have ben found in the current Automation Framework configuration.",
        "It may be missing from default. An empty context is created",
    )
    # something failed: create an empty one and return it
    if not af["env"]:
        af["env"] = {}
    if not af["env"].get("contexts"):
        af["env"]["contexts"] = []
    af["env"]["contexts"].append({"name": context})
    return ensure_default(af["env"]["contexts"][-1])
