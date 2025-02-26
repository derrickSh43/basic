pipeline {
    agent any

    environment {
        AWS_REGION = 'us-east-1'
        SONARQUBE_URL = "https://sonarcloud.io"
        JIRA_SITE = "https://derrickweil.atlassian.net"
        JIRA_PROJECT = "JENKINS"
        ARTIFACTORY_URL = "https://trialu47lau.jfrog.io/artifactory"
        ARTIFACTORY_REPO = "tf--terraform-modules-local"
        NAMESPACE = "derrickweil"
        MODULE_NAME = "your-module-name"
        VERSION = "1.1"
        VAULT_ADDR = "http://54.235.6.210:8200"
        JFROG_CLI_BUILD_NAME = "basic-build"  // Build name for JFrog
        JFROG_CLI_BUILD_NUMBER = "${BUILD_NUMBER}"  // Jenkins build number
    }

    stages {

stage('Fetch Vault Credentials') {
            steps {
                script {
                    withVault(
                        configuration: [
                            vaultUrl: "${VAULT_ADDR}",
                            vaultCredentialId: 'vault-approle'
                        ],
                        vaultSecrets: [
                            [path: 'secret/aws-creds', secretValues: [
                                [envVar: 'AWS_ACCESS_KEY_ID', vaultKey: 'access_key'],
                                [envVar: 'AWS_SECRET_ACCESS_KEY', vaultKey: 'secret_key']
                            ]],
                            [path: 'secret/sonarqube', secretValues: [
                                [envVar: 'SONAR_TOKEN_TEMP', vaultKey: 'token']
                            ]],
                            [path: 'secret/snyk', secretValues: [
                                [envVar: 'SNYK_TOKEN_TEMP', vaultKey: 'token']
                            ]],
                            [path: 'secret/jfrog', secretValues: [
                                [envVar: 'ARTIFACTORY_USER_TEMP', vaultKey: 'username'],
                                [envVar: 'ARTIFACTORY_API_KEY_TEMP', vaultKey: 'api_key']
                            ]]
                        ]
                    ) {
                        env.SONAR_TOKEN = "${SONAR_TOKEN_TEMP}"
                        env.SNYK_TOKEN = "${SNYK_TOKEN_TEMP}"
                        env.ARTIFACTORY_USER = "${ARTIFACTORY_USER_TEMP}"
                        env.ARTIFACTORY_API_KEY = "${ARTIFACTORY_API_KEY_TEMP}"
                        echo "Static secrets fetched successfully"
                    }
                }
            }
        }

        stage('Fetch AWS STS Credentials') {
            steps {
                script {
                    withCredentials([
                        string(credentialsId: 'vault-role-id', variable: 'VAULT_ROLE_ID'),
                        string(credentialsId: 'vault-secret-id', variable: 'VAULT_SECRET_ID')
                    ]) {
                        sh '''
                            set +x  # Disable command echoing
                            export VAULT_TOKEN=$(vault write -field=token auth/approle/login role_id="$VAULT_ROLE_ID" secret_id="$VAULT_SECRET_ID")
                            vault read -format=json aws/creds/jenkins-role > sts_creds.json
                            export AWS_ACCESS_KEY_ID=$(jq -r '.data.access_key' sts_creds.json)
                            export AWS_SECRET_ACCESS_KEY=$(jq -r '.data.secret_key' sts_creds.json)
                            export AWS_SESSION_TOKEN=$(jq -r '.data.security_token' sts_creds.json)
                            echo "STS credentials fetched successfully"
                        '''
                    }
                }
            }
        }    
        
        stage('Checkout Code') {
            steps {
                git branch: 'main', url: 'https://github.com/derrickSh43/basic.git'
            }
        }

        stage('Static Code Analysis (SonarQube)') {
            steps {
                script {
                    def scanStatus = sh(script: """
                        set +x
                        ${SONAR_SCANNER_HOME}/bin/sonar-scanner \\
                        -Dsonar.projectKey=derrickSh43_basic \\
                        -Dsonar.organization=derricksh43 \\
                        -Dsonar.host.url=${SONARQUBE_URL} \\
                        -Dsonar.login=${SONAR_TOKEN}
                    """, returnStatus: true)

                    if (scanStatus != 0) {
                        def sonarIssuesRaw = sh(script: """
                            set +x
                            curl -s -u ${SONAR_TOKEN}: \\
                            "${SONARQUBE_URL}/api/issues/search?componentKeys=derrickSh43_basic&severities=BLOCKER,CRITICAL&statuses=OPEN" | jq -r '.issues[]'
                        """, returnStdout: true).trim()

                        if (sonarIssuesRaw) {
                            def sonarIssues = readJSON(text: "[${sonarIssuesRaw.split('\n').join(',')}]")
                            if (sonarIssues.size() > 0) {
                                def issueDetails = sonarIssues.collect { issue ->
                                    def filePath = issue.component.split(':').last()
                                    def line = issue.line ?: 'N/A'
                                    def snippet = "Code snippet not implemented"  // Replace with getCodeSnippet if available
                                    "Issue: ${issue.message}\\nFile: ${filePath}\\nLine: ${line}\\nSnippet:\\n${snippet}"
                                }.join('\\n\\n')
                                echo "SonarQube issues found - creating JIRA ticket"
                                sh "echo 'Would create JIRA ticket with details'"  // Replace with createJiraTicket
                                env.SCAN_FAILED = "true"
                            }
                        }
                    } else {
                        echo "SonarQube scan completed successfully"
                    }
                }
            }
        }
            
        

stage('Snyk Security Scan') {
            steps {
                script {
                    def snykStatus = sh(script: """
                        set +x
                        export SNYK_TOKEN=${SNYK_TOKEN}
                        snyk iac test --json --severity-threshold=low > snyk-results.json 2>&1
                    """, returnStatus: true)

                    def snykOutput = readFile('snyk-results.json').trim()
                    if (snykStatus != 0 || (snykOutput && !snykOutput.startsWith('['))) {
                        echo "Snyk scan failed or produced invalid JSON"
                        if (snykOutput) {
                            echo "Snyk output: ${snykOutput}"
                        }
                        env.SCAN_FAILED = "true"
                    } else {
                        def snykIssuesList = readJSON(file: "snyk-results.json").infrastructureAsCodeIssues
                        if (snykIssuesList?.size() > 0) {
                            def issueDetails = snykIssuesList.collect { issue ->
                                def filePath = issue.filePath ?: 'N/A'
                                def line = issue.lineNumber ?: 'N/A'
                                def snippet = "Code snippet not implemented"
                                "Issue: ${issue.title}\\nSeverity: ${issue.severity}\\nFile: ${filePath}\\nLine: ${line}\\nImpact: ${issue.impact}\\nResolution: ${issue.resolution}\\nSnippet:\\n${snippet}"
                            }.join('\\n\\n')
                            echo "Snyk issues found - creating JIRA ticket"
                            sh "echo 'Would create JIRA ticket with details'"
                            env.SCAN_FAILED = "true"
                        } else {
                            echo "No Snyk issues detected"
                        }
                    }
                    sh "rm -f snyk-results.json"
                }
            }
        }

 stage('Build Artifact') {
            steps {
                sh 'echo "Building artifact..."'
                sh 'mkdir -p dist && echo "dummy content" > dist/test.zip'
            }
        }
        stage('Upload Artifact to JFrog') {
            steps {
                sh """
                    set +x
                    jfrog rt upload "dist/*.zip" "${ARTIFACTORY_REPO}/${NAMESPACE}/${MODULE_NAME}/${VERSION}/" \\
                    --url="${ARTIFACTORY_URL}" --user="${ARTIFACTORY_USER}" --apikey="${ARTIFACTORY_API_KEY}"
                """
            }
        }
stage('JFrog Xray Scan') {
            steps {
                script {
                    def xrayStatus = sh(script: """
                        set +x
                        jfrog rt bs \\
                        --url="${ARTIFACTORY_URL}" \\
                        --user="${ARTIFACTORY_USER}" \\
                        --apikey="${ARTIFACTORY_API_KEY}" \\
                        "${JFROG_CLI_BUILD_NAME}" "${JFROG_CLI_BUILD_NUMBER}" > xray-scan.json 2>&1
                    """, returnStatus: true)

                    def xrayOutput = readFile('xray-scan.json').trim()
                    if (xrayStatus != 0 || (xrayOutput && !xrayOutput.startsWith('{'))) {
                        echo "JFrog Xray scan failed or produced invalid JSON"
                        if (xrayOutput) {
                            echo "Xray output: ${xrayOutput}"
                        }
                        env.SCAN_FAILED = "true"
                    } else {
                        def xrayResults = readJSON(file: "xray-scan.json")
                        def xrayIssues = xrayResults.violations ?: []
                        if (xrayIssues.size() > 0) {
                            def issueDetails = xrayIssues.collect { issue ->
                                "Issue: ${issue.summary}\\nSeverity: ${issue.severity}\\nDescription: ${issue.description}\\nCVE: ${issue.cve ?: 'N/A'}"
                            }.join('\\n\\n')
                            echo "JFrog Xray violations found - creating JIRA ticket"
                            sh "echo 'Would create JIRA ticket with details'"
                            env.SCAN_FAILED = "true"
                        } else {
                            echo "No JFrog Xray violations detected"
                        }
                    }
                    sh "rm -f xray-scan.json"
                }
            }
        }
    
    

        stage('Fail Pipeline if Scans Fail') {
            steps {
                script {
                    if (env.SCAN_FAILED == "true") {
                        error("Security vulnerabilities detected! Check Jira for details.")
                    }
                }
            }
        }
    }

    post {
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}

def createJiraTicket(String issueTitle, String issueDescription) {
    def jqlQuery = "project = ${JIRA_PROJECT} AND summary ~ \\\"${issueTitle}\\\" AND status != Closed"
    def searchResponse = sh(script: """
        curl -s -u "${JIRA_USER}:${JIRA_TOKEN}" \
        -H "Content-Type: application/json" \
        "${JIRA_SITE}/rest/api/3/search?jql=${jqlQuery}&fields=key,summary,status" | jq -r '.issues[] | .key' || echo ""
    """, returnStdout: true).trim()

    if (searchResponse) {
        echo "Existing Jira ticket found: ${searchResponse}"
        return searchResponse
    }

    def jiraPayload = """
    {
        "fields": {
            "project": { "key": "${JIRA_PROJECT}" },
            "summary": "${issueTitle}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": "${issueDescription}"}]}]
            },
            "issuetype": { "name": "Bug" }
        }
    }
    """
    writeFile file: 'jira_payload.json', text: jiraPayload

    def createResponse = sh(script: """
        curl -X POST "${JIRA_SITE}/rest/api/3/issue" \
        -u "${JIRA_USER}:${JIRA_TOKEN}" \
        -H "Content-Type: application/json" \
        --data @jira_payload.json
    """, returnStdout: true).trim()

    def createdIssue = readJSON(text: createResponse)
    if (!createdIssue.containsKey("key")) {
        error("Failed to create Jira ticket! Response: ${createResponse}")
    }

    echo "New Jira ticket created: ${createdIssue.key}"
    return createdIssue.key
}

def getCodeSnippet(String filePath, String lineNumber) {
    if (filePath == 'N/A' || lineNumber == 'N/A') return null
    try {
        def lineNum = lineNumber.toInteger()
        def fileContent = readFile(file: filePath).split('\n')
        def startLine = Math.max(0, lineNum - 2) // 2 lines before
        def endLine = Math.min(fileContent.size() - 1, lineNum + 1) // 1 line after
        return fileContent[startLine..endLine].join('\n')
    } catch (Exception e) {
        echo "Failed to get code snippet for ${filePath}:${lineNumber} - ${e.message}"
        return null
    }
}