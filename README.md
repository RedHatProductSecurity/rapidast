# RapiDAST

RapiDAST provides a framework for continuous, proactive and fully automated dynamic scanning against web apps/API.

Its core engine is OWASP ZAP Proxy (https://owasp.org/www-project-zap/). Taking advantage of the ZAP container, this project provides value as follows:
 - Easy automation(via fully working in CLI with yaml configuration) of API scanning based on OAS definition
 - Create users' own custom rules via yaml files
 - XML, HTML, JSON report generation

# Prerequisites

podman or docker is required.

## For podman
```
$ pip3 install podman-compose
$ podman pull docker.io/owasp/zap2docker-stable
```

# Quick Scan Example(using podman)

1. Get a URL for the OAS3 definition file
2. Get a URL for the target API
3. Create config.yaml with the URLs and place it in config/
4. Set the API_KEY value in .env file
5. zaproxy container must be running (either runenv.sh or runenv-ui.sh)
```
$ ./runenv.sh
```

Run in the project root directory,
```
$ test/scan-example-with-podman.sh <dir_to_store_results>
```

When a scan is completed, its report will be generated in the `results/<dir_to_store_results>`

## Example
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
XML report saved in: /zap/results/testrun/demo1-report-20211210-041924.xml

$ ls -al results/testrun
total 48
-rw-r--r--. 1 fedora fedora 9198 Dec 13 08:11 demo1-report-20211210-041924.xml
drwxr-xr-x. 7 fedora fedora  140 Dec 13 08:11 sessions
```

# Usage

## podman

### Run as daemon

#### Run a container

```
$ podman-compose -f podman-compose.yml up
$ podman unshare chown 1000 ./results (podman bind volumes as container root while the app runs as container zap user)
```

#### Launch a scan
```
$ podman exec zaproxy python /zap/scripts/apis_scan.py <dirname_to_be_created_under_results_dir>
```

#### Stopping Environments
```
$ podman-compose -f podman-compose.yml down
```

### Run with GUI (useful for debugging)
This is taking advantage of ZAP's webswing feature. See https://www.zaproxy.org/docs/docker/webswing/.

#### Run a container
```
$ podman-compose -f podman-compose-ui.yml up
$ podman unshare chown 1000 ./results (podman bind volumes as container root while the app runs as container zap user)
```
After the step, it is necessary to navigate to the GUI via http://127.0.0.1:8081/zap to start an actual ZAP instance.

#### Create a custom rule

It is possible to create a custom rule yaml file and apply to the ZAP instance. Refer to a few examples of the yaml rule files in the scripts/gen-zap-script/rules directory.

Apply custom rules to the running ZAP instance before launching a scan.

##### Example: Load and enable custom rule
```
$ podman exec zaproxy python scripts/gen-zap-script/cli.py --from-yaml scripts/gen-zap-script/rules/software_version_revealed.yaml --rapidast-config=<config-file> --load-and-enable
```

##### Example: Delete existing custom rules
```
$ podman exec zaproxy python scripts/gen-zap-script/cli.py --rapidast-config=<config-file> --delete
```

#### Launch a scan
```
$ podman exec zaproxy python /zap/scripts/apis_scan.py <dirname_to_be_created_under_results_dir>
```


#### Stopping Environments
```
$ podman-compose -f podman-compose-ui.yml down
```

## docker

### Run as daemon

#### Run a container

```
$ docker-compose up zaproxy

```

#### Launch a scan
```
$ docker-compose exec zaproxy python /zap/scripts/apis_scan.py <dirname_to_be_created_under_results_dir>
```

#### Stopping Environments
```
$ docker-compose down
```

### Run with GUI (useful for debugging)
This is taking advantage of ZAP's webswing feature. See https://www.zaproxy.org/docs/docker/webswing/.

#### Run a container
```
$ docker-compose up zaproxy_ui
```
After the step, it is necessary to navigate to the GUI via http://127.0.0.1:8081/zap to start an actual ZAP instance.

#### Launch a scan
```
$ docker-compose exec zaproxy_ui python /zap/scripts/apis_scan.py <dirname_to_be_created_under_results_dir>
```

#### Stopping Environments
```
$ docker-compose down
```
