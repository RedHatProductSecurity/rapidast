# RapiDAST

RapiDAST provides a framework for continuous, proactive and fully automated dynamic scanning against web apps/API.

Its core engine is OWASP ZAP Proxy (https://owasp.org/www-project-zap/). Taking advantage of the ZAP container, this project provides value as follows:
 - Easy automation(via fully working in CLI with yaml configuration) of API scanning based on OAS definition
 - Ability to run the automated API scanning on Kubernetes (or Red Hat OpenShift)
 - Ability to create custom rules via yaml files
 - HTML, JSON report generation (XML is also possible)

# Prerequisites

* podman or docker is required.
* podman-compose or docker-compose is required.
* Pull the OWASP ZAP docker image
```
$ podman pull docker.io/owasp/zap2docker-stable
```

# Basic workflow for a scan
1. Create config.yaml, place it in config/ and set the config values for your API. You can use config/config-template-local.yaml as an example
2. Get OAS3/Swagger definition files (either URL or in the directory specified in config[openapi][directory] in the config.yaml file)
3. Set the target URL in config.yaml
4. Create an .env file in the project root and set the API_KEY and other variables as necessary in it

## .env file example

```
# This file will set environment variables inside zaproxy container

# API KEY should be set to ensure that public instances of ZAP can only be
# accessed by the intended clients
API_KEY=[GENERATE_RANDOM_STRING]

# oauth2 refresh_token used in authMethod: 'scriptBasedAuthentication' in config.yaml
#RTOKEN=[oauth_refresh_token]

# set this to handle basic auth when authMethod: null in config.yaml
# ZAP_AUTH_HEADER_VALUE=Basic [base64_encoded_creds]
```


# Quick Scan Example(using podman)

zaproxy container must be running (either runenv.sh or runenv-ui.sh)
1. Get a URL for the OAS3 definition file
2. Get a URL for the target API
3. Create config.yaml with the URLs and place it in config/
4. Set the API_KEY value in .env file
5. zaproxy container must be running (either runenv.sh or runenv-ui.sh)

```
$ ./runenv.sh
```

6. Launch a scan in the project root directory,
```
$ test/scan-example-with-podman.sh <dir_to_store_results>
```

When a scan is completed, its report will be generated in the `results/<dir_to_store_results>`

## Example of a scan run
```
$ test/scan-example-with-podman.sh testrun                
Deleting previously generated scripts                                              
Loading the script to ZAP                                                          
Templating script Rule_Gen_05eec230-5ba0-4bf5-b1d0-43268b8542d2                    
Loading script Rule_Gen_05eec230-5ba0-4bf5-b1d0-43268b8542d2 in ZAP from /tmp/Rule_Gen_05eec230-5ba0-4bf5-b1d0-43268b8542d25k5s0yj7.js                                 
Enabling script Rule_Gen_05eec230-5ba0-4bf5-b1d0-43268b8542d2 in ZAP               
Script Rule_Gen_05eec230-5ba0-4bf5-b1d0-43268b8542d2 successfully loaded and enabled                                                                                   
Creating session in: /zap/results/testrun/sessions/20211210-041924/session1          
Excluded URLs: ^(?:(?!http://192.168.109.202:9000).*).$                               
Include URL in context: http://192.168.109.202:9000/api/.*                            
Exclude URL from context:                                                          
Importing API: /zap/config/oas/openapi.json                                        
>> Target Url: http://192.168.109.202:9000                                            
Start Active scan. Scan ID equals 0                                                
Scan Policies: ['API-minimal-example']                                             
Active Scan progress: 0%                                                           
Active Scan completed                                                                                                                                                  
Waiting for Passive Scan to complete                                                                                                                                   
Passive Scan completed                                                             
JSON report saved in: /zap/results/testrun/demo1-report-20220722-033427.json                                                                                                                                                                          
HTML report saved in: /zap/results/testrun/demo1-report-20220722-033427.html
```

# Usage

While the following examples are shown based on podman, the same commands can be replaced with docker and docker-compose.

## for podman users only

You will need to make the host's `./result` directory writable to the `zap` user in the container. This can be done with the following command. For docker users, this is not necessary.
```
$ podman unshare chown 1000 ./results
```

See [this](https://docs.podman.io/en/latest/markdown/podman-unshare.1.html) for more information on `podman unshare`.

## Run as daemon

### Run a container

```
$ podman-compose -f podman-compose.yml up
```

On older podman versions (before 3.1.0), you will need to manually make the `./result` directory writable to the `zap` user. This can be done with the following command. For docker users, this is not necessary.
```
$ podman unshare chown 1000 ./results
```

### Launch a scan
```
$ podman exec zaproxy python /zap/scripts/apis_scan.py <dirname_to_be_created_under_results_dir>
```

### Stopping Environments
```
$ podman-compose -f podman-compose.yml down
```

## Run with GUI (useful for debugging)
This is taking advantage of ZAP's webswing feature. See https://www.zaproxy.org/docs/docker/webswing/.

### Run a container
```
$ podman-compose -f podman-compose-ui.yml up
```


After the step, it is necessary to navigate to the GUI via http://127.0.0.1:8081/zap to start an actual ZAP instance.


### Launch a scan
```
$ podman exec zaproxy python /zap/scripts/apis_scan.py <dirname_to_be_created_under_results_dir>
```

### Stopping Environments
```
$ podman-compose -f podman-compose-ui.yml down
```

## Create a custom rule

It is possible to create a custom rule yaml file and apply to the ZAP instance. Refer to a few examples of the yaml rule files in the scripts/gen_zap_script/rules directory.

Apply custom rules to the running ZAP instance before launching a scan.

### Example: Load and enable custom rule
```
$ podman exec zaproxy python scripts/gen_zap_script/cli.py --from-yaml scripts/gen_zap_script/rules/software_version_revealed.yaml --rapidast-config=<config-file> --load-and-enable
```

### Example: Delete existing custom rules
```
$ podman exec zaproxy python scripts/gen_zap_script/cli.py --rapidast-config=<config-file> --delete
```


## Run RapiDast as a GitHub action for CI

You can find an example of an action in .github/workflows/rapidast-scan.yml.
This action will run using docker. To config this follow this steps:

1. Follow the "Prerequisites" section
2. Set GitHub secret named "AUTH_CRED" with the base64 basic authentication credentials for the API to scan. For example:
```
dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=
```
**IMPORTANT**: this action will upload the scan results as action artifacts. This contains info about the intercepted HTTP requests by ZAP which will contain your AUTH_CRED secret value in the Authorization header


## RapiDAST Operator

See [this](https://github.com/RedHatProductSecurity/rapidast/blob/development/operator/README.md) for more information.

# Contributing

Contribution to the project is more than welcome. 

See [CONTRIBUTING.md](./CONTRIBUTING.md)
