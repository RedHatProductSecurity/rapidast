#!/usr/bin/env python3
import os, sys, json, time
from datetime import datetime
from pprint import pprint
from zapv2 import ZAPv2
import subprocess

from config import *

contextID = ''

def createSession(session_name):
    # Start the ZAP session
    print ("Creating session in: " + session_name)
    zap.core.new_session(name=session_name, overwrite=True)

    # Configure ZAP global Exclude URL option
    for excludeUrl in globalExcludeUrl:
        print ("Excluded URLs: " + excludeUrl)
        zap.core.exclude_from_proxy(regex=excludeUrl)

    # Configure ZAP outgoing proxy server connection option
    if useProxyChain:
        zap.core.set_option_proxy_chain_name(string=proxyAddress)
        zap.core.set_option_proxy_chain_port(integer=proxyPort)
        zap.core.set_option_proxy_chain_skip_name(string=skipProxyAddresses)

        print ("Setting Upstream Proxy to: " + proxyAddress + ":" +  proxyPort)
        zap.core.set_option_use_proxy_chain(boolean=useProxyChain)

def enable_httpsender_script():
    script = zap.script
    script.remove(scriptname=HttpSenderScriptName)
    pprint('Load httpsender script: ' + HttpSenderScriptName + ' -> ' +
            script.load(scriptname=HttpSenderScriptName, scripttype='httpsender',
                scriptengine=HttpSenderScriptEngine,
                filename=HttpSenderScriptFilePath,
                scriptdescription=HttpSenderScriptDescription))
    pprint('Enable httpsender script: ' + HttpSenderScriptName + ' -> ' +
            script.enable(scriptname=HttpSenderScriptName))

def createContext():
    context = zap.context
    context.remove_context('Default Context')
    contextID = context.new_context(contextname=contextName)

    # Include URL in the context
    for includeUrl in contextIncludeURL:
        print ("Include URL in context: " + includeUrl)
        context.include_in_context(contextname=contextName,
                                   regex=includeUrl)

    # Exclude URL in the context
    for excludeUrl in contextExcludeURL:
        print ("Exclude URL from context: " + excludeUrl)
        context.exclude_from_context(contextname=contextName,
                                     regex=excludeUrl)

    ## In case we use the scriptBasedAuthentication method, load the script
    if authMethod == 'scriptBasedAuthentication':
        script = zap.script
        script.remove(scriptname=authScriptName)
        pprint('Load script: ' + authScriptName + ' -> ' +
                script.load(scriptname=authScriptName,
                            scripttype='authentication',
                            scriptengine=authScriptEngine,
                            filename=authScriptFilePath,
                            scriptdescription=authScriptDescription))

        # Define an authentication method with parameters for the context
        auth = zap.authentication
        pprint('Set authentication method: ' + authMethod + ' -> ' +
                auth.set_authentication_method(contextid=contextID,
                                               authmethodname=authMethod,
                                               authmethodconfigparams=authParams))
        # Define either a loggedin indicator or a loggedout indicator regexp
        # It allows ZAP to see if the user is always authenticated during scans
        if authIsLoggedInIndicator:
            pprint('Define Loggedin indicator: ' + authIndicatorRegex + ' -> ' +
                    auth.set_logged_in_indicator(contextid=contextID,
                                            loggedinindicatorregex=authIndicatorRegex))
        else:
            pprint('Define Loggedout indicator: ' + authIndicatorRegex + ' -> ' +
                    auth.set_logged_out_indicator(contextid=contextID,
                                            loggedoutindicatorregex=authIndicatorRegex))

        # Create a testuser for script authentication.
        if authCreateUser:
            users = zap.users

            userIdList = []

            rtoken = os.getenv('RTOKEN')
            userList = [
                {'name': 'test1', 'credentials': 'refresh_token=' + rtoken}
            ]
            for user in userList:
                userName = user.get('name')
                print('Create user ' + userName + ':')
                userId = users.new_user(contextid=contextID, name=userName)
                userIdList.append(userId)
                pprint('User ID: ' + userId + '; username -> ' +
                        users.set_user_name(contextid=contextID, userid=userId,
                                            name=userName) +
                        '; credentials -> ' +
                        users.set_authentication_credentials(contextid=contextID,
                            userid=userId,
                            authcredentialsconfigparams=user.get('credentials')) +
                        '; enabled -> ' +
                        users.set_user_enabled(contextid=contextID, userid=userId,
                                                enabled=True))

                zap.forcedUser.set_forced_user(contextID, userId)

            zap.forcedUser.set_forced_user_mode_enabled(True)

    # end if authMethod == 'scriptBasedAuthentication'


def enablePassiveScanner():
    zap.pscan.enable_all_scanners()
    zap.pscan.disable_scanners(disabledPassiveScan)

    #print ("DEBUG: pscan list")
    #for scanner in zap.pscan.scanners:
    #    if (scanner.get("enabled") == "true"):
    #        print (scanner.get("id") + " : " + scanner.get("enabled") + " : " + scanner.get("name"))

def getAPIs():
  
    if oasImportFromUrl:
        print ("Importing API from URL: " + oasUrl)

        try:
            zap.openapi.import_url(oasUrl, target)
        except:
            print("Something is wrong while importing OpenAPI")
            exit()
        
        # for easier debugging
        time.sleep(1)
    else:
        apis = os.listdir(oasDir)

        if len(apis) > 0:
            found_oas_file = False
            oas_file_suffixes = (".json", ".yaml", ".yml")

            for api in apis:

                if not api.lower().endswith(oas_file_suffixes):
                    print("unsupported file is in the OpenAPI definition directory: " + api)
                    continue

                found_oas_file = True

                with open(oasDir + '/' + api) as f:
                    print ("Importing API: " + oasDir + '/' + api)

                    print (">> Target Url: " + target)
                    zap.openapi.import_file(oasDir + '/' + api, target)

                    # for easier debugging
                    time.sleep(1)
            if not found_oas_file:
                print("Missing .json or .yaml or .yml OpenAPI definitions")
                exit()
        else:
            print("No files in the specified OAS directory")
            exit()

def startActiveScanner():
    policies = os.listdir(appDir + '/policies')
    if len(policies) > 0:
        #add policies
        for policy in policies:
            zap.ascan.import_scan_policy(path=appDir + '/policies/'+ policy)

        #remove other policies
        for existingPolicie in zap.ascan.scan_policy_names:
            if existingPolicie != scanPolicyName:
                zap.ascan.remove_scan_policy(scanpolicyname=existingPolicie)

    else:
        print("Missing Scan Policies. Add them to policies folder")
        exit()

    #configure active scan options
    zap.ascan.set_option_host_per_scan(3)
    zap.ascan.set_option_thread_per_host(20)
    # Launch Active scan with the configured policy on the target url and
    # recursively scan every site node
    scanId = zap.ascan.scan(url=target, recurse=True, inscopeonly=True,
        scanpolicyname=scanPolicyName, method=None, postdata=True, contextid=contextID)

    print('Start Active scan. Scan ID equals ' + scanId)
    print("Scan Policies: " + str(zap.ascan.scan_policy_names))
    while (int(zap.ascan.status(scanId)) < 100):
        print('Active Scan progress: ' + zap.ascan.status(scanId) + '%')
        time.sleep(10) 
    print('Active Scan completed')



def startSpider():
    print("Access target URL: " + target)
    zap.core.access_url(url=applicationURL, followredirects=True)
    time.sleep(2)

    print('Starting Spider on target: ' + applicationURL)
    scanId = zap.spider.scan(contextname=contextName, url=applicationURL, maxchildren=None,
        recurse=True, subtreeonly=None)
    time.sleep(2)

    while (int(zap.spider.status(scanId)) < 100):
        print('Spider progress ' + zap.spider.status(scanId) + '%')
        time.sleep(2)
    print('Spider scan completed')

def waitForPassiveScanner():
    print('Waiting for Passive Scan to complete')

    while int(zap.pscan.records_to_scan) > 0:
        print('Remaining records to passive scan: ' + zap.pscan.records_to_scan)
        time.sleep(2)

    print('Passive Scan completed')


def generateReport(scan_time_str):
    report = appDir + workDir + serviceName + '-report-' + scan_time_str + ".xml"
    f = open(report, "w")
    f.write(zap.core.xmlreport())

    f.close()
    print('XML report saved in: ' + report)



if __name__ == "__main__":

    workDir = resultDir + sys.argv[1] + '/'

    try:
        zap = ZAPv2(proxies=localProxy, apikey=apiKey)
    except:
        print("Can't connet to ZAP. Is it running and proxying on localhost:8090?")
        exit()

    scan_time_str = datetime.now().strftime("%Y%m%d-%H%M%S")
    session_fullpath_name = appDir + workDir + 'sessions/'+ scan_time_str + '/' + sessionName

    createSession(session_fullpath_name)

    if authMethod == 'scriptBasedAuthentication':
        enable_httpsender_script()

    createContext()
    enablePassiveScanner()
    getAPIs()
    time.sleep(5)

    startActiveScanner()
    waitForPassiveScanner()

    #Save the session until the next run
    zap.core.save_session(name=session_fullpath_name, overwrite=True)

    generateReport(scan_time_str)


    if shutdownOnceFinished:
        # Shutdown ZAP once finished
        print('Shutdown ZAP -> ' + zap.core.shutdown())
