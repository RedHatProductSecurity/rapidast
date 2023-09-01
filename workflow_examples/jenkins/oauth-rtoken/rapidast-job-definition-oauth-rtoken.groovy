// This is an example implemtation of how we could rapidast in jenkins
// This job doesn't expose all the rapidast options but gives us an idea on how it could be used in jenkins pipeline job

pipelineJob('rapidast-scan-job') {
    displayName('Rapidast Scanner Job')
    description('Job will help scan services for Vulnerabilities with rapidast')
        properties {
        disableConcurrentBuilds()
    }
    parameters {
        stringParam('SERVICENAME','','Required. Service Name that is scanned (No spaces/special char allowed)')
        stringParam('API_SCANNER','OpenApiScan','Required. Currently only OpenApi Spec)')
        nonStoredPasswordParam('RTOKEN','Required. Request token to access the service API. ')
        stringParam('TARGET_URL', '', 'Starting point of URL Ex. http://localhost:9000/api/ ')
        stringParam('SSO_ENDPOINT','','Required. Endpoint of the Authentication with Oauth')
        stringParam('CLIENT_ID', '', 'Client_id required for jwt auth')
        stringParam('PROXY', '', 'Optional, Ex. localhost:9090')
        stringParam('API_SPEC_URL', '', 'Url where the openapi is present. Ex. http://localhost:9001/openapi.yaml')
    }
    logRotator {
        numToKeep(50)
    }
    definition {
        cps {
            script(readFileFromWorkspace('workflow_examples/jenkins/rapidastscan.groovy'))
            sandbox()
        }
    }
}
