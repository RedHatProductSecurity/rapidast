#!/usr/bin/env groovy


podTemplate(
        containers: [
            containerTemplate(
                name: 'rapidast',
                image: "quay.io/redhatproductsecurity/rapidast:2.2.1",
                resourceRequestCpu: '2',
                resourceLimitCpu: '3',
                resourceRequestMemory: '1Gi',
                resourceLimitMemory: '3Gi',
                ttyEnabled: true,
                command: 'cat',
                alwaysPullImage: true,
                ),
            ],
        showRawYaml: true,
        serviceAccount: "jenkins",
        cloud: defaults.cloud
    ) {

        node(POD_LABEL) {
            container("rapidast") {
                stage("Install Rapidast for ${SERVICENAME}") {
                     currentBuild.displayName = "#"+ env.BUILD_NUMBER + " " + "${SERVICENAME}"
                }

                stage("Inject configs for  Service") {
                    parse_rapidast_options("${SERVICENAME}", "${API_SCANNER}", "${TARGET_URL}", "${API_SPEC_URL}", "${CLIENT_ID}", "${SSO_ENDPOINT}", "${PROXY}")
                }

                stage("Run Rapidast for service") {
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        withCredentials([string(credentialsId: 'RTOKEN', variable: 'RTOKEN')])  {
                            writeFile file: '.env', text: "RTOKEN=${RTOKEN}"
                            sh "./rapidast.py --log-level debug --config config/config.yaml"
                        }
                    }
                }

                stage("Collect artifacts") {
                    archiveArtifacts allowEmptyArchive: true, artifacts: "results/${SERVICENAME}/**/zap/*.*, results.html"
                }
            }
        }
    }


def parse_rapidast_options(String ServiceName, String ApiScanner, String TargetUrl, String ApISpecUrl, String CLIENT_ID, String SSO_ENDPOINT, String Proxy) {
    // Parse the options for rapidast and add it to the config file. Always pull the latest config file

    git url: 'https://github.com/RedHatProductSecurity/rapidast.git', branch: 'main'
    def filename = 'config/config-template-long.yaml'
    // Comment the fields not required.
    sh "sed -i 's/importUrlsFromFile:/# importUrlsFromFile:/' ${filename}"
    sh "sed -i 's/defectDojoExport:/# defectDojoExport:/' ${filename}"
    sh "sed -i 's/# format:/format:/' ${filename}"
    if ("${ApiScanner}" == "OpenApiScan") {
        // Comment the fields not required.
        echo "OpenAPI Spec Compliant API Scan selected"
        sh "sed -i 's/graphql:/# graphql:/' ${filename}"
        sh "sed -i 's/spiderAjax:/# spiderAjax:/' ${filename}"
        sh "sed -i 's/spider:/# spider:/' ${filename}"
    }
    else {
        echo "Scanner not supported."
        currentBuild.result = 'FAILURE'
        sh "exit 1"
    }
    // Read the YAML and them populate the fields
    def data = readYaml file: filename

    data.config.environ = ".env"
    data.application.shortName = "${ServiceName}"
    data.application.url = "${TargetUrl}"
    data.general.authentication.parameters.client_id = "${CLIENT_ID}"
    data.general.authentication.parameters.token_endpoint = "${SSO_ENDPOINT}"
    data.general.container.type = "none"
    data.scanners.zap.apiScan.target = "${TargetUrl}"
    data.scanners.zap.apiScan.apis.apiUrl = "${ApISpecUrl}"
    data.scanners.zap.miscOptions.oauth2OpenapiManualDownload = "True"

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
