// This is an example implemtation of how we could rapidast in Jenkins
// This job doesn't expose all the rapidast options but gives us an idea on how it could be used in Jenkins pipeline job

pipelineJob('rapidast-simple-openapi-scan-job') {
    displayName('RapiDAST Simple OpenAPI Scan Jenkins Job')
    description('Job will help scan API for Vulnerabilities with RapiDAST, using OpenAPI spec doc')
        properties {
        disableConcurrentBuilds()
    }
    parameters {
        stringParam('SERVICENAME','','Required. Service Name that is scanned (No spaces/special char allowed)')
        stringParam('TARGET_URL', '', 'Starting point of URL Ex. http://localhost:9000/api/ ')
        stringParam('API_SPEC_URL', '', 'Url where the openapi is present. Ex. http://localhost:9001/openapi.yaml')
        stringParam('PROXY', '', 'Optional, Ex. localhost:9090')
    }
    logRotator {
        numToKeep(50)
    }
    definition {
        cps {
            script(readFileFromWorkspace('/path/to/workflow_examples/jenkins/simple/rapidastscan.groovy'))
            sandbox()
        }
    }
}
