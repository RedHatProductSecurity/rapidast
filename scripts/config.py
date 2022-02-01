import yaml

with open("./config/config.yaml", "r") as stream:
    try:
        config = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        raise RuntimeError(
            "Something went wrong parsing the config.yaml file: " + str(exc)
        )

serviceName = config["general"]["serviceName"]
apiKey = config["general"]["apiKey"]
appDir = config["general"]["appDir"]
localProxy = config["general"]["localProxy"]
sessionName = config["general"]["sessionName"]
shutdownOnceFinished = config["general"]["shutdownOnceFinished"]
resultDir = config["general"]["resultDir"]

if "proxy" in config:
    useProxyChain = config["proxy"]["useProxyChain"]
    proxyAddress = config["proxy"]["proxyAddress"]
    proxyPort = config["proxy"]["proxyPort"]
    skipProxyAddresses = config["proxy"]["skipProxyAddresses"]
else:
    useProxyChain = False

if "openapi" in config:
    oasImportFromUrl = config["openapi"]["importFromUrl"]
    if oasImportFromUrl:
        oasUrl = config["openapi"]["url"]
    else:
        oasDir = config["openapi"]["directory"]


contextName = config["scan"]["contextName"]
target = config["scan"]["target"]
applicationURL = config["scan"]["applicationURL"]

# globalExcludeUrl is generated from 'target', which excludes every single URL that doesn't belong to the target domain, to avoid accidentally hitting production
# example: ['^(?:(?!https:\/\/www.target.com).*).$']
globalExcludeUrl = ["^(?:(?!" + target + ").*).$"]

contextIncludeURL = config["scan"]["contextIncludeURL"]
contextExcludeURL = config["scan"]["contextExcludeURL"]
scanPoliciesDir = appDir + config["scan"]["policies"]["scanPoliciesDir"]
scanPolicyName = config["scan"]["policies"]["scanPolicyName"]
disabledPassiveScan = config["scan"]["policies"]["disabledPassiveScan"]

################# AUTHENTICATION ######
authMethod = config["scan"]["authMethod"]

if authMethod == "scriptBasedAuthentication":
    # MANDATORY only if authMethod is set to scriptBasedAuthentication.
    authScriptName = config["scan"]["scriptAuth"]["authScriptName"]
    # Script engine values: Oracle Nashorn for Javascript
    # jython for python, JSR 223 JRuby Engine for ruby
    authScriptEngine = config["scan"]["scriptAuth"]["authScriptEngine"]
    # Absolute local path
    authScriptFilePath = config["scan"]["scriptAuth"]["authScriptFilePath"]
    authScriptDescription = config["scan"]["scriptAuth"]["authScriptDescription"]

    # Each name/value pair of authParams are expected to be "x-www-form-urlencoded"
    # Here is an example for scriptBasedAuthentication method:

    authTokenEndpoint = config["scan"]["scriptAuth"]["authTokenEndpoint"]
    authClientID = config["scan"]["scriptAuth"]["authClientID"]
    authParams = (
        "scriptName=" + authScriptName + "&"
        "token_endpoint=" + authTokenEndpoint + "&client_id=" + authClientID
    )

    authCreateUser = config["scan"]["scriptAuth"]["authCreateUser"]

    authIsLoggedInIndicator = config["scan"]["scriptAuth"]["authIsLoggedInIndicator"]
    authIndicatorRegex = config["scan"]["scriptAuth"]["authIndicatorRegex"]

    # HTTP Sender script
    useHttpSenderScript = config["scan"]["scriptAuth"]["useHttpSenderScript"]
    HttpSenderScriptName = config["scan"]["scriptAuth"]["HttpSenderScriptName"]
    HttpSenderScriptEngine = config["scan"]["scriptAuth"]["HttpSenderScriptEngine"]
    HttpSenderScriptFilePath = config["scan"]["scriptAuth"]["HttpSenderScriptFilePath"]
    HttpSenderScriptDescription = config["scan"]["scriptAuth"][
        "HttpSenderScriptDescription"
    ]
