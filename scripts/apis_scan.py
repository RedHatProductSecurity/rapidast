#!/usr/bin/env python3
import os
import sys
import time
import logging
from datetime import datetime
from zapv2 import ZAPv2
import argparse

from config import *

context_id = ""


def create_session(session_name):
    # Start the ZAP session
    logging.info("Creating session in: " + session_name)
    zap.core.new_session(name=session_name, overwrite=True)

    # Configure ZAP global Exclude URL option
    for excludeUrl in globalExcludeUrl:
        logging.info("Excluded URLs: " + excludeUrl)
        zap.core.exclude_from_proxy(regex=excludeUrl)

    # Configure ZAP outgoing proxy server connection option
    if useProxyChain:
        zap.core.set_option_proxy_chain_name(string=proxyAddress)
        zap.core.set_option_proxy_chain_port(integer=proxyPort)
        zap.core.set_option_proxy_chain_skip_name(string=skipProxyAddresses)

        logging.info("Setting Upstream Proxy to: " + proxyAddress + ":" + proxyPort)
        zap.core.set_option_use_proxy_chain(boolean=useProxyChain)


def enable_httpsender_script():
    script = zap.script
    script.remove(scriptname=HttpSenderScriptName)
    logging.info(
        "Load httpsender script: "
        + HttpSenderScriptName
        + " -> "
        + script.load(
            scriptname=HttpSenderScriptName,
            scripttype="httpsender",
            scriptengine=HttpSenderScriptEngine,
            filename=HttpSenderScriptFilePath,
            scriptdescription=HttpSenderScriptDescription,
        )
    )
    logging.info(
        "Enable httpsender script: "
        + HttpSenderScriptName
        + " -> "
        + script.enable(scriptname=HttpSenderScriptName)
    )


def create_context():
    global context_id
    context = zap.context
    context.remove_context("Default Context")
    context_id = context.new_context(contextname=contextName)

    # Include URL in the context
    for includeUrl in contextIncludeURL:
        logging.info("Include URL in context: " + includeUrl)
        context.include_in_context(contextname=contextName, regex=includeUrl)

    # Exclude URL in the context
    for excludeUrl in contextExcludeURL:
        logging.info("Exclude URL from context: " + excludeUrl)
        context.exclude_from_context(contextname=contextName, regex=excludeUrl)

    # In case we use the scriptBasedAuthentication method, load the script
    if authMethod == "scriptBasedAuthentication":
        script = zap.script
        script.remove(scriptname=authScriptName)
        logging.info(
            "Load script: "
            + authScriptName
            + " -> "
            + script.load(
                scriptname=authScriptName,
                scripttype="authentication",
                scriptengine=authScriptEngine,
                filename=authScriptFilePath,
                scriptdescription=authScriptDescription,
            )
        )

        # Define an authentication method with parameters for the context
        auth = zap.authentication
        logging.info(
            "Set authentication method: "
            + authMethod
            + " -> "
            + auth.set_authentication_method(
                contextid=context_id,
                authmethodname=authMethod,
                authmethodconfigparams=authParams,
            )
        )
        # Define either a loggedin indicator or a loggedout indicator regexp
        # It allows ZAP to see if the user is always authenticated during scans
        if authIsLoggedInIndicator:
            logging.info(
                "Define Loggedin indicator: "
                + authIndicatorRegex
                + " -> "
                + auth.set_logged_in_indicator(
                    contextid=context_id, loggedinindicatorregex=authIndicatorRegex
                )
            )
        else:
            logging.info(
                "Define Loggedout indicator: "
                + authIndicatorRegex
                + " -> "
                + auth.set_logged_out_indicator(
                    contextid=context_id, loggedoutindicatorregex=authIndicatorRegex
                )
            )

        # Create a testuser for script authentication.
        if authCreateUser:
            users = zap.users

            user_id_list = []

            rtoken = os.getenv("RTOKEN")
            user_list = [{"name": "test1", "credentials": "refresh_token=" + rtoken}]
            for user in user_list:
                user_name = user.get("name")
                logging.info("Create user " + user_name + ":")
                user_id = users.new_user(contextid=context_id, name=user_name)
                user_id_list.append(user_id)
                logging.info(
                    "User ID: "
                    + user_id
                    + "; username -> "
                    + users.set_user_name(
                        contextid=context_id, userid=user_id, name=user_name
                    )
                    + "; credentials -> "
                    + users.set_authentication_credentials(
                        contextid=context_id,
                        userid=user_id,
                        authcredentialsconfigparams=user.get("credentials"),
                    )
                    + "; enabled -> "
                    + users.set_user_enabled(
                        contextid=context_id, userid=user_id, enabled=True
                    )
                )

                zap.forcedUser.set_forced_user(context_id, user_id)

            zap.forcedUser.set_forced_user_mode_enabled(True)


def enable_passive_scanner():
    zap.pscan.enable_all_scanners()
    zap.pscan.disable_scanners(disabledPassiveScan)


def get_APIs():
    if oasImportFromUrl:
        logging.info("Importing API from URL: " + oasUrl)

        try:
            count = 1
            while count <= 3:
                ret = zap.openapi.import_url(oasUrl, target)
                if ret == []:
                    break
                logging.warning(f"ZAP import OpenAPI {oasUrl} failed (returned '{ret}'). It may be due to bad authentication. Attempt {count}/3")
                count = count + 1
                time.sleep(3)
        except Exception as e:
            raise RuntimeError(
                "Something went wrong while importing OpenAPI: " + str(e)
            )

        # for easier debugging
        time.sleep(1)
    else:
        apis = os.listdir(oasDir)

        if len(apis) > 0:
            found_oas_file = False
            oas_file_suffixes = (".json", ".yaml", ".yml")

            for api in apis:

                if not api.lower().endswith(oas_file_suffixes):
                    logging.warning(
                        "unsupported file is in the OpenAPI definition directory: "
                        + api
                    )
                    continue

                found_oas_file = True

                with open(oasDir + "/" + api) as f:
                    logging.info("Importing API: " + oasDir + "/" + api)

                    logging.info(">> Target Url: " + target)
                    zap.openapi.import_file(oasDir + "/" + api, target)

                    # for easier debugging
                    time.sleep(1)
            if not found_oas_file:
                raise RuntimeError("Missing .json or .yaml or .yml OpenAPI definitions")
        else:
            raise RuntimeError("No files in the specified OAS directory")


def start_active_scanner():
    policies = os.listdir(appDir + "/policies")
    if len(policies) > 0:
        # add policies
        for policy in policies:
            if ( zap.ascan.import_scan_policy(path=appDir + "/policies/" + policy) == 'already_exists' ):
                logging.warning(f"The policy {policy} was already in ZAP. No modification were applied to the existing policy")


        # remove other policies
        for existing_policy in zap.ascan.scan_policy_names:
            if existing_policy != scanPolicyName:
                zap.ascan.remove_scan_policy(scanpolicyname=existing_policy)

    else:
        raise RuntimeError("Missing Scan Policies. Add them to policies folder")

    # configure active scan options
    zap.ascan.set_option_host_per_scan(3)
    zap.ascan.set_option_thread_per_host(20)
    # Launch Active scan with the configured policy on the target url and
    # recursively scan every site node
    scan_id = zap.ascan.scan(
        url=target,
        recurse=True,
        inscopeonly=True,
        scanpolicyname=scanPolicyName,
        method=None,
        postdata=True,
        contextid=context_id,
    )

    try:
        int(scan_id)
    except ValueError:
        raise RuntimeError(
            "Could not create scan for target {}, ZAP returned: {}".format(
                target, scan_id
            )
        )

    logging.info("Start Active scan. Scan ID equals " + scan_id)
    logging.info("Scan Policies: " + str(zap.ascan.scan_policy_names))
    while int(zap.ascan.status(scan_id)) < 100:
        logging.info("Active Scan progress: " + zap.ascan.status(scan_id) + "%")
        time.sleep(10)
    logging.info("Active Scan completed")


def start_spider():
    logging.info("Access target URL: " + target)
    zap.core.access_url(url=applicationURL, followredirects=True)
    time.sleep(2)

    logging.info("Starting Spider on target: " + applicationURL)
    scan_id = zap.spider.scan(
        contextname=contextName,
        url=applicationURL,
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
    report = appDir + workDir + serviceName + "-report-" + scan_timestamp + ".xml"
    f = open(report, "w")
    f.write(zap.core.xmlreport())

    f.close()
    logging.info("XML report saved in: " + report)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Connect to ZAP and launch a scan based on config.yaml')
    parser.add_argument('--log-level', dest='loglevel', 
            choices=["debug","info","warning","error","critical"], 
            default="info", help='Level of verbosity')
    parser.add_argument('destination', metavar='NAME',
            help=f"Directory of the report, relative to {resultDir}")

    logging.basicConfig(level=parser.parse_args().loglevel.upper())

    workDir = resultDir + parser.parse_args().destination + "/"

    try:
        zap = ZAPv2(proxies=localProxy, apikey=apiKey)
    except Exception:
        raise RuntimeError(
            "Can't connect to ZAP. Is it running and proxying on localhost:8090?"
        )

    scan_time_str = datetime.now().strftime("%Y%m%d-%H%M%S")
    session_fullpath_name = (
        appDir + workDir + "sessions/" + scan_time_str + "/" + sessionName
    )

    create_session(session_fullpath_name)

    if authMethod == "scriptBasedAuthentication":
        enable_httpsender_script()

    create_context()
    enable_passive_scanner()
    get_APIs()
    time.sleep(5)

    start_active_scanner()
    wait_for_passive_scanner()

    # Save the session until the next run
    zap.core.save_session(name=session_fullpath_name, overwrite=True)

    generate_report(scan_time_str)

    if shutdownOnceFinished:
        # Shutdown ZAP once finished
        logging.info("Shutdown ZAP -> " + zap.core.shutdown())
