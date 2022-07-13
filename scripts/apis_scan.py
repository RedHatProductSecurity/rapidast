#!/usr/bin/env python3
import argparse
import logging
import os
import time
from datetime import datetime

from zapv2 import ZAPv2

try:
    from . import config
except ImportError:
    import config

CONTEXT_ID = ""


def create_session(session_name):
    # Start the ZAP session
    logging.info("Creating session in: " + session_name)
    zap.core.new_session(name=session_name, overwrite=True)

    # Configure ZAP global Exclude URL option
    for exclude_url in config.GLOBAL_EXCLUDE_URL:
        logging.info("Excluded URLs: " + exclude_url)
        zap.core.exclude_from_proxy(regex=exclude_url)

    # Configure ZAP outgoing proxy server connection option
    if config.USE_PROXY_CHAIN:
        zap.core.set_option_proxy_chain_name(string=config.PROXY_ADDRESS)
        zap.core.set_option_proxy_chain_port(integer=config.PROXY_PORT)
        zap.core.set_option_proxy_chain_skip_name(string=config.SKIP_PROXY_ADDRESSES)

        logging.info(f"Setting Upstream Proxy to: {config.PROXY_ADDRESS}:{config.PROXY_PORT}")
        zap.core.set_option_use_proxy_chain(boolean=config.USE_PROXY_CHAIN)


def enable_httpsender_script():
    script = zap.script
    script.remove(scriptname=config.HTTP_SENDER_SCRIPT_NAME)
    logging.info(
        "Load httpsender script: "
        + config.HTTP_SENDER_SCRIPT_NAME
        + " -> "
        + script.load(
            scriptname=config.HTTP_SENDER_SCRIPT_NAME,
            scripttype="httpsender",
            scriptengine=config.HTTP_SENDER_SCRIPT_ENGINE,
            filename=config.HTTP_SENDER_SCRIPT_FILE_PATH,
            scriptdescription=config.HTTP_SENDER_SCRIPT_DESCRIPTION,
        )
    )
    logging.info(
        "Enable httpsender script: "
        + config.HTTP_SENDER_SCRIPT_NAME
        + " -> "
        + script.enable(scriptname=config.HTTP_SENDER_SCRIPT_NAME)
    )


def create_context():
    global CONTEXT_ID
    context = zap.context
    context.remove_context("Default Context")
    CONTEXT_ID = context.new_context(contextname=config.CONTEXT_NAME)

    # Include URL in the context
    for include_url in config.CONTEXT_INCLUDE_URL:
        logging.info(f"Include URL in context: {include_url}")
        context.include_in_context(contextname=config.CONTEXT_NAME, regex=include_url)

    # Exclude URL in the context
    for exclude_url in config.CONTEXT_EXCLUDE_URL:
        logging.info(f"Exclude URL from context: {exclude_url}")
        context.exclude_from_context(contextname=config.CONTEXT_EXCLUDE_URL, regex=exclude_url)

    # In case we use the scriptBasedAuthentication method, load the script
    if config.AUTH_METHOD == "scriptBasedAuthentication":
        script = zap.script
        script.remove(scriptname=config.AUTH_SCRIPT_NAME)
        logging.info(
            "Load script: "
            + config.AUTH_SCRIPT_NAME
            + " -> "
            + script.load(
                scriptname=config.AUTH_SCRIPT_NAME,
                scripttype="authentication",
                scriptengine=config.AUTH_SCRIPT_ENGINE,
                filename=config.AUTH_SCRIPT_FILE_PATH,
                scriptdescription=config.AUTH_SCRIPT_DESCRIPTION,
            )
        )

        # Define an authentication method with parameters for the context
        auth = zap.authentication
        logging.info(
            "Set authentication method: "
            + config.AUTH_METHOD
            + " -> "
            + auth.set_authentication_method(
                contextid=CONTEXT_ID,
                authmethodname=config.AUTH_METHOD,
                authmethodconfigparams=config.AUTH_PARAMS,
            )
        )
        # Define either a loggedin indicator or a loggedout indicator regexp
        # It allows ZAP to see if the user is always authenticated during scans
        if config.AUTH_IS_LOGGED_IN_INDICATOR:
            logging.info(
                "Define Loggedin indicator: "
                + config.AUTH_INDICATOR_REGEX
                + " -> "
                + auth.set_logged_in_indicator(contextid=CONTEXT_ID, loggedinindicatorregex=config.AUTH_INDICATOR_REGEX)
            )
        else:
            logging.info(
                "Define Loggedout indicator: "
                + config.AUTH_INDICATOR_REGEX
                + " -> "
                + auth.set_logged_out_indicator(
                    contextid=CONTEXT_ID, loggedoutindicatorregex=config.AUTH_INDICATOR_REGEX
                )
            )

        # Create a testuser for script authentication.
        if config.AUTH_CREATE_USER:
            users = zap.users

            user_id_list = []

            rtoken = os.getenv("RTOKEN")
            user_list = [{"name": "test1", "credentials": f"refresh_token={rtoken}"}]
            for user in user_list:
                user_name = user.get("name")
                logging.info(f"Create user {user_name}:")
                user_id = users.new_user(contextid=CONTEXT_ID, name=user_name)
                user_id_list.append(user_id)
                logging.info(
                    "User ID: "
                    + user_id
                    + "; username -> "
                    + users.set_user_name(contextid=CONTEXT_ID, userid=user_id, name=user_name)
                    + "; credentials -> "
                    + users.set_authentication_credentials(
                        contextid=CONTEXT_ID,
                        userid=user_id,
                        authcredentialsconfigparams=user.get("credentials"),
                    )
                    + "; enabled -> "
                    + users.set_user_enabled(contextid=CONTEXT_ID, userid=user_id, enabled=True)
                )

                zap.forcedUser.set_forced_user(CONTEXT_ID, user_id)

            zap.forcedUser.set_forced_user_mode_enabled(True)


def enable_passive_scanner():
    zap.pscan.set_scan_only_in_scope(True)
    zap.pscan.enable_all_scanners()
    zap.pscan.disable_scanners(config.DISABLED_PASSIVE_SCAN)


def import_urls(filepath):
    """
    Imports URLs (one per line) from the file with the given file system path.
    This component is optional and therefore the API will only work if it is installed
    """
    return zap._request(f"{zap.base}exim/action/importUrls", {"filePath": filepath})  # pylint: disable=W0212


def get_apis():
    if config.URL_SCAN:
        url_list_path = f"/zap{config.URL_SCAN_DIR}/urlScan.config"
        logging.info("Scanning from URL List")
        import_urls(url_list_path)
    elif config.OAS_IMPORT_FROM_URL:
        logging.info(f"Importing API from URL: {config.OAS_URL}")

        try:
            count = 1
            while count <= 3:
                ret = zap.openapi.import_url(config.OAS_URL, config.TARGET)
                if ret == []:
                    break
                logging.warning(
                    f"ZAP import OpenAPI {config.OAS_URL} failed (returned '{ret}'). "
                    "It may be due to bad authentication. Attempt {count}/3"
                )
                count += 1
                time.sleep(3)
        except Exception as e:
            raise RuntimeError("Something went wrong while importing OpenAPI: \n\n" + str(e)) from e

        # for easier debugging
        time.sleep(1)
    else:
        apis = os.listdir(config.OAS_DIR)

        if len(apis) > 0:
            found_oas_file = False
            oas_file_suffixes = (".json", ".yaml", ".yml")

            for api in apis:

                if not api.lower().endswith(oas_file_suffixes):
                    logging.warning(f"unsupported file is in the OpenAPI definition directory: {api}")
                    continue

                found_oas_file = True

                with open(f"{config.OAS_DIR}/{api}", encoding="utf-8"):
                    logging.info(f"Importing API: {config.OAS_DIR}/{api}")

                    logging.info(f">> Target Url: {config.TARGET}")
                    zap.openapi.import_file(f"{config.OAS_DIR}/{api}", config.TARGET)

                    # for easier debugging
                    time.sleep(1)
            if not found_oas_file:
                raise RuntimeError("Missing .json or .yaml or .yml OpenAPI definitions")
        else:
            raise RuntimeError("No files in the specified OAS directory")


def check_scan_id(scan_id):
    try:
        int(scan_id)
    except ValueError as e:
        raise RuntimeError(f"Could not create scan for target {config.TARGET}, ZAP returned: {scan_id}") from e


def start_active_scanner():
    policies = os.listdir(f"{config.APP_DIR}/policies")
    if len(policies) > 0:
        # add policies
        for policy in policies:
            if zap.ascan.import_scan_policy(path=f"{config.APP_DIR}/policies/{policy}") == "already_exists":
                logging.warning(
                    f"The policy {policy} was already in ZAP. No modification were applied to the existing policy"
                )

        # remove other policies
        for existing_policy in zap.ascan.scan_policy_names:
            if existing_policy != config.SCAN_POLICY_NAME:
                zap.ascan.remove_scan_policy(scanpolicyname=existing_policy)

    else:
        raise RuntimeError("Missing Scan Policies. Add them to policies folder")

    # configure active scan options
    zap.ascan.set_option_host_per_scan(3)
    zap.ascan.set_option_thread_per_host(20)
    # Launch Active scan with the configured policy on the target url and
    # recursively scan every site node
    scan_id = None
    if config.URL_SCAN:
        url_list_path = f"/zap{config.URL_SCAN_DIR}/urlScan.config"
        with open(url_list_path, "r", encoding="UTF-8") as file:
            while line := file.readline().rstrip():
                scan_id = zap.ascan.scan(
                    url=line,
                    recurse=True,
                    inscopeonly=True,
                    scanpolicyname=config.SCAN_POLICY_NAME,
                    method=None,
                    postdata=True,
                    contextid=CONTEXT_ID,
                )
                check_scan_id(scan_id)
    else:
        scan_id = zap.ascan.scan(
            url=config.TARGET,
            recurse=True,
            inscopeonly=True,
            scanpolicyname=config.SCAN_POLICY_NAME,
            method=None,
            postdata=True,
            contextid=CONTEXT_ID,
        )
        check_scan_id(scan_id)

    try:
        int(scan_id)
    except ValueError as e:
        raise RuntimeError(f"Could not create scan for target {config.TARGET}, ZAP returned: {scan_id}") from e

    logging.info("Start Active scan. Scan ID equals " + scan_id)
    logging.info("Scan Policies: " + str(zap.ascan.scan_policy_names))
    while int(zap.ascan.status(scan_id)) < 100:
        logging.info("Active Scan progress: " + zap.ascan.status(scan_id) + "%")
        time.sleep(10)
    logging.info("Active Scan completed")


def start_spider():
    logging.info(f"Access target URL: {config.TARGET}")
    zap.core.access_url(url=config.APPLICATION_URL, followredirects=True)
    time.sleep(2)

    logging.info(f"Starting Spider on target: {config.APPLICATION_URL}")
    scan_id = zap.spider.scan(
        contextname=config.CONTEXT_NAME,
        url=config.APPLICATION_URL,
        maxchildren=None,
        recurse=True,
        subtreeonly=None,
    )
    time.sleep(2)

    while int(zap.spider.status(scan_id)) < 100:
        logging.info("Spider progress " + zap.spider.status(scan_id) + "%")
        time.sleep(2)
    logging.info("Spider scan completed")


def wait_for_passive_scanner():
    logging.info("Waiting for Passive Scan to complete")

    while int(zap.pscan.records_to_scan) > 0:
        logging.debug("Remaining records to passive scan: " + zap.pscan.records_to_scan)
        time.sleep(2)

    logging.info("Passive Scan completed")


def generate_report(scan_timestamp):
    report = f"{config.APP_DIR}{work_dir}/{config.SERVICE_NAME}-report-{scan_timestamp}.json"
    with open(report, "w", encoding="utf-8") as f:
        f.write(zap.core.jsonreport())
        logging.info(f"JSON report saved in: {report}")

    report = f"{config.APP_DIR}{work_dir}/{config.SERVICE_NAME}-report-{scan_timestamp}.html"
    with open(report, "w", encoding="utf-8") as f:
        f.write(zap.core.htmlreport())
        logging.info(f"HTML report saved in: {report}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Connect to ZAP and launch a scan based on config.yaml")
    parser.add_argument(
        "--log-level",
        dest="loglevel",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="Level of verbosity",
    )
    parser.add_argument(
        "destination",
        metavar="NAME",
        help=f"Directory of the report, relative to {config.RESULT_DIR}",
    )

    logging.basicConfig(level=parser.parse_args().loglevel.upper())

    work_dir = f"{config.RESULT_DIR}{parser.parse_args().destination}"

    try:
        zap = ZAPv2(proxies=config.LOCAL_PROXY, apikey=config.API_KEY)
    except Exception as error:
        raise RuntimeError("Can't connect to ZAP. Is it running and proxying on localhost:8090?") from error

    scan_time_str = datetime.now().strftime("%Y%m%d-%H%M%S")
    session_fullpath_name = f"{config.APP_DIR}{work_dir}/sessions/{scan_time_str}/{config.SESSION_NAME}"

    create_session(session_fullpath_name)

    if config.USE_HTTP_SENDER_SCRIPT:
        logging.info("use_http_sender")
        enable_httpsender_script()

    create_context()
    enable_passive_scanner()
    get_apis()
    time.sleep(5)

    start_active_scanner()
    wait_for_passive_scanner()

    # Save the session until the next run
    zap.core.save_session(name=session_fullpath_name, overwrite=True)

    generate_report(scan_time_str)

    if config.SHUTDOWN_ONCE_FINISHED:
        # Shutdown ZAP once finished
        logging.info("Shutdown ZAP -> " + zap.core.shutdown())
