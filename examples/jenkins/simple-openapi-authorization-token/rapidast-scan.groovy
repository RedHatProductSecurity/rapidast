#!/usr/bin/env groovy

podTemplate(
        containers: [
            containerTemplate(
                name: 'rapidast',
                image: 'quay.io/redhatproductsecurity/rapidast:2.2.1',
                command: 'cat',
                ttyEnabled: true
                ),
            ]) {

        node(POD_LABEL) {
            container("rapidast") {
                stage("Install Rapidast for ${SERVICENAME}") {

                     currentBuild.displayName = "#"+ env.BUILD_NUMBER + " " + "${SERVICENAME}"
                }

                stage("Inject configs for  Service") {
                    // 'sample-scan-auth-token' must be created in the Jenkins Credentials menu
                    withCredentials([string(credentialsId: 'sample-scan-auth-token', variable: 'AUTH_TOKEN')])  {
                        configure_rapidast("${SERVICENAME}", "${TARGET_URL}", "${API_SPEC_URL}", "${AUTH_TOKEN}", "${PROXY}")
                    }
                }

                stage("Run Rapidast for service") {
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        sh "rapidast.py --config config/config.yaml"
                    }
                }

               stage("Collect artifacts") {
                    archiveArtifacts allowEmptyArchive: true, artifacts: "results/${SERVICENAME}/**/zap/*.*, results.html, config/config.yaml"
               }

            }
        }
    }


def configure_rapidast(String ServiceName, String TargetUrl, String ApISpecUrl, String AuthToken, String Proxy) {
    // Parse the options for rapidast and add it to the config file. Always pull the latest config file
    // Currently support OpenAPI based scan only

    git url: 'https://github.com/RedHatProductSecurity/rapidast.git', branch: 'main'
    def filename = 'config/config-template.yaml'

    // Read the YAML and them populate the fields
    def data = readYaml file: filename

    data.config.environ = ".env"
    data.application.shortName = "${ServiceName}"
    data.application.url = "${TargetUrl}"
    data.general.authentication.type = "http_header"
    data.general.authentication.parameters.name = "Authorization"
    data.general.authentication.parameters.value = "${AuthToken}"
    data.general.container.type = "none"
    data.scanners.zap.apiScan.target = "${TargetUrl}"
    data.scanners.zap.apiScan.apis.apiUrl = "${ApISpecUrl}"

    if (Proxy) {
        String[] proxyarr;
        proxyarr = Proxy.split(':');
        data.general.proxy.proxyHost = proxyarr[0]
        data.general.proxy.proxyPort = proxyarr[1]
    }
    //create new with updated YAML config
    writeYaml file: 'config/config.yaml', data: data
    echo "Configuration Value: " + data
}
