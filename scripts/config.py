import os

import yaml


with open("./config/config.yaml", "r", encoding="utf-8") as stream:
    try:
        config = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        raise RuntimeError("Something went wrong parsing the config.yaml file: \n\n" + str(exc)) from exc

SERVICE_NAME = config["general"]["serviceName"]
API_KEY = os.getenv("API_KEY")
APP_DIR = config["general"]["appDir"]
LOCAL_PROXY = config["general"]["localProxy"]
SESSION_NAME = config["general"]["sessionName"]
SHUTDOWN_ONCE_FINISHED = config["general"]["shutdownOnceFinished"]
RESULT_DIR = config["general"]["resultDir"]

if "proxy" in config:
    USE_PROXY_CHAIN = config["proxy"]["useProxyChain"]
    PROXY_ADDRESS = config["proxy"]["proxyAddress"]
    PROXY_PORT = config["proxy"]["proxyPort"]
    SKIP_PROXY_ADDRESSES = config["proxy"]["skipProxyAddresses"]
else:
    USE_PROXY_CHAIN = False

if "openapi" in config:
    OAS_IMPORT_FROM_URL = config["openapi"]["importFromUrl"]
    if OAS_IMPORT_FROM_URL:
        OAS_URL = config["openapi"]["url"]
    else:
        OAS_DIR = config["openapi"]["directory"]

if "urlscan" in config:
    URL_SCAN_DIR = config["urlscan"]["urlScanDir"]
    URL_SCAN = config["urlscan"]["urlScan"]
else:
    URL_SCAN_DIR = None
    URL_SCAN = False


CONTEXT_NAME = config["scan"]["contextName"]
TARGET = config["scan"]["target"]
APPLICATION_URL = config["scan"]["applicationURL"]

# globalExcludeUrl is generated from 'target', which excludes every single URL that doesn't belong to the target domain,
# to avoid accidentally hitting production
# example: ['^(?:(?!https:\/\/www.target.com).*).$']
GLOBAL_EXCLUDE_URL = [f"^(?:(?!{TARGET}).*).$"]

CONTEXT_INCLUDE_URL = config["scan"]["contextIncludeURL"]
CONTEXT_EXCLUDE_URL = config["scan"]["contextExcludeURL"]
SCAN_POLICIES_DIR = f"{APP_DIR}{config['scan']['policies']['scanPoliciesDir']}"
SCAN_POLICY_NAME = config["scan"]["policies"]["scanPolicyName"]
DISABLED_PASSIVE_SCAN = config["scan"]["policies"]["disabledPassiveScan"]

################# AUTHENTICATION ######
AUTH_METHOD = config["scan"]["authMethod"]

if AUTH_METHOD == "scriptBasedAuthentication":
    # MANDATORY only if authMethod is set to scriptBasedAuthentication.
    AUTH_SCRIPT_NAME = config["scan"]["scriptAuth"]["authScriptName"]
    # Script engine values: Oracle Nashorn for Javascript
    # jython for python, JSR 223 JRuby Engine for ruby
    AUTH_SCRIPT_ENGINE = config["scan"]["scriptAuth"]["authScriptEngine"]
    # Absolute local path
    AUTH_SCRIPT_FILE_PATH = config["scan"]["scriptAuth"]["authScriptFilePath"]
    AUTH_SCRIPT_DESCRIPTION = config["scan"]["scriptAuth"]["authScriptDescription"]

    # Each name/value pair of authParams are expected to be "x-www-form-urlencoded"
    # Here is an example for scriptBasedAuthentication method:

    AUTH_TOKEN_ENDPOINT = config["scan"]["scriptAuth"]["authTokenEndpoint"]
    AUTH_CLIENT_ID = config["scan"]["scriptAuth"]["authClientID"]
    AUTH_PARAMS = f"scriptName={AUTH_SCRIPT_NAME}&token_endpoint={AUTH_TOKEN_ENDPOINT}&client_id={AUTH_CLIENT_ID}"

    AUTH_CREATE_USER = config["scan"]["scriptAuth"]["authCreateUser"]

    AUTH_IS_LOGGED_IN_INDICATOR = config["scan"]["scriptAuth"]["authIsLoggedInIndicator"]
    AUTH_INDICATOR_REGEX = config["scan"]["scriptAuth"]["authIndicatorRegex"]

    # HTTP Sender script
    USE_HTTP_SENDER_SCRIPT = config["scan"]["scriptAuth"]["useHttpSenderScript"]
    HTTP_SENDER_SCRIPT_NAME = config["scan"]["scriptAuth"]["HttpSenderScriptName"]
    HTTP_SENDER_SCRIPT_ENGINE = config["scan"]["scriptAuth"]["HttpSenderScriptEngine"]
    HTTP_SENDER_SCRIPT_FILE_PATH = config["scan"]["scriptAuth"]["HttpSenderScriptFilePath"]
    HTTP_SENDER_SCRIPT_DESCRIPTION = config["scan"]["scriptAuth"]["HttpSenderScriptDescription"]
