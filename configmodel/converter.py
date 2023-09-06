import copy
import logging

import configmodel

# WARNING: this needs to be incremented everytime a non-compatible change is made in the configuration.
# A corresponding function also needs to be written
CURR_CONFIG_VERSION = 5


def config_converter_dispatcher(func):
    """This is intended to be a decorator to register functions to convert configuration to a newer schema version
    The function passed during creation will be called in case no suitable functions are found.
    i.e.: it should raise an error.

    It is possible to retrieve an updater function by calling <dispatcher>.dispatch(<version>)
    """
    registry = {}  # version -> function()

    registry[-1] = func

    def register(version):
        def inner(func):
            registry[version] = func
            return func

        return inner

    def decorator(conf):
        version = int(conf.get("config.configVersion", 0))
        func = registry.get(version, registry[-1])
        return func(conf)

    def dispatch(version):
        return registry.get(version, registry[-1])

    decorator.register = register
    decorator.registry = registry
    decorator.dispatch = dispatch

    return decorator


@config_converter_dispatcher
def convert_configmodel(conf):
    """This is the base function, attached to error reporting"""
    version = conf.get("config.configVersion", 0)
    raise RuntimeError(
        f"There was an error in converting configuration. No convertion available for version {version}"
    )


@convert_configmodel.register(4)
def convert_from_version_4_to_5(old):
    """Returns a *copy* of the original rapidast config file, but updated to v5
    scanner.zap.miscOptions.oauth2OpenapiManualDownload was renamed oauth2ManualDownload

    Note: scanners can now have IDs (i.e.: scanner.zap_foo, not just scanner.zap)
    """
    new = copy.deepcopy(old)

    for key in old.conf["scanners"]:
        if key.startswith("zap") and old.exists(
            f"scanners.{key}.miscOptions.oauth2OpenapiManualDownload"
        ):
            new.move(
                f"scanners.{key}.miscOptions.oauth2OpenapiManualDownload",
                f"scanners.{key}.miscOptions.oauth2ManualDownload",
            )

    # Finally, set the correct version number
    new.set("config.configVersion", 5)

    return new


@convert_configmodel.register(3)
def convert_from_version_3_to_4(old):
    """Returns a *copy* of the original rapidast config file, but updated to v4
    Changes: Now any entry can be optionally appended with `_from_var`.
    `oauth2_rtoken` authentication can now piggy back on this feature, so the original entry is removed
    """
    new = copy.deepcopy(old)
    new.move(
        "scanners.zap.authentication.parameters.rtoken_var_name",
        "scanners.zap.authentication.parameters.rtoken_from_var",
    )
    new.move(
        "general.authentication.parameters.rtoken_var_name",
        "general.authentication.parameters.rtoken_from_var",
    )

    # Finally, set the correct version number
    new.set("config.configVersion", 4)

    return new


@convert_configmodel.register(2)
def convert_from_version_2_to_3(old):
    """Returns a *copy* of the original rapidast config file, but updated to v3
    Change: `scanners.zap.updateAddons` moved to `scanners.zap.miscOptions.updateAddons`
    """
    new = copy.deepcopy(old)
    new.move("scanners.zap.updateAddons", "scanners.zap.miscOptions.updateAddons")

    # Finally, set the correct version number
    new.set("config.configVersion", 3)

    return new


@convert_configmodel.register(1)
def convert_from_version_1_to_2(old):
    """Returns a *copy* of the original rapidast config file, but updated to v2
    Change: `scanners.*.container.image` was moved to `scanners.*.container.parameters.image`
    """
    new = copy.deepcopy(old)

    # We need to move all scanners.*.container.image
    # In practice, currently, there's only `zap` to worry about
    for key in old.conf["scanners"]:
        new.move(
            f"scanners.{key}.container.image",
            f"scanners.{key}.container.parameters.image",
        )

    # This should not happen: image is not meant to be stored there, but just to be clean
    new.move("general.container.image", "general.container.parameters.image")

    # Finally, set the correct version number
    new.set("config.configVersion", 2)

    return new


@convert_configmodel.register(0)
def convert_from_version_0_to_1(old):
    """Returns a *copy* of the original rapidast config file, but updated to v1"""

    logging.warning(
        "Converting from the original rapidast v1 config file only best effort. Please review the result manually"
    )

    if old.get("config.configVersion", default=0) > 0:
        logging.warning("version fix: unexpected version number")

    # not for version 0: better to start from scratch
    # new = copy.deepcopy(old)
    new = configmodel.RapidastConfigModel()
    new.set("config", {"environ": ".env"})
    new.set(
        "application",
        {
            "shortName": old.get("general.serviceName", default="myApp"),
            "url": old.get("scan.target", default=""),
        },
    )

    # "general" section
    new.set("general", {})

    ## "proxy" section
    if old.get("proxy.useProxyChain", default=False):
        new.set(
            "general.proxy",
            {
                "proxyHost": old.get("proxy.proxyAddress", default=""),
                "proxyPort": old.get("proxy.proxyPort", default=""),
            },
        )

    ## authentication
    auth_method = old.get("scan.auth_method", default=None)
    if (
        auth_method == "scriptBasedAuthentication"
        and old.get("scan.scriptAuth.authScriptFilePath", default="")
        == "scripts/offline-token.js"
    ):
        # probably OAuth2
        new.set(
            "general.authentication",
            {
                "type": "oauth2_rtoken",
                "parameters": {
                    "client_id": old.get(
                        "scan.scriptAuth.authClientID", default="cloud-services"
                    ),
                    "token_endpoint": old.get(
                        "scan.scriptAuth.authTokenEndpoint", default=""
                    ),
                    "rtoken_var_name": "RTOKEN",
                },
            },
        )
    else:
        logging.warning(
            "The config version translator does not support this particular authentication"
        )

    # "Scanners.Zap" section
    new.set(
        "scanners.zap",
        {"apiScan": None},
    )

    ### OpenAPI
    if old.get("openapi.importFromUrl", default=False):
        new.set(
            "scanners.zap.apiScan.apis.apiUrl", old.get("openapi.url", default=None)
        )
    elif old.get("openapi.directory", default=""):
        logging.warning(
            "The config version translator does not support Directory based OpenAPI"
        )

    ## Passive scan
    new.set("scanners.zap.passiveScan", {})
    # Add in the disabled rules
    new.set(
        "scanners.zap.passiveScan.disabledRules",
        old.get("scan.policies.disabledPassiveScan", ""),
    )

    ## Active scan
    # Active scanner was always enabled, so we do the same:
    new.set("scanners.zap.activeScan", {})
    new.set(
        "scanners.zap.activeScan.policy", old.get("scan.policies.scanPolicyName", None)
    )

    # Finally, set the correct version number
    new.set("config.configVersion", 1)

    return new


def update_to_latest_config(config):
    """Update `config` to version CURR_CONFIG_VERSION, and return it"""

    if int(config.get("config.configVersion", default=0)) > CURR_CONFIG_VERSION:
        raise RuntimeError("Config file unsupported: configVersion is too high")

    while int(config.get("config.configVersion", default=0)) < CURR_CONFIG_VERSION:
        # Update config schema, one version at a time
        config = convert_configmodel(config)
    logging.debug("Successful config schema update")
    return config
