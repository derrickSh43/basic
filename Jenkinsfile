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
        VAULT_ADDR = "http://3.91.233.45:8200"
    }

    stages {
        stage('Fetch Vault Token') {
            steps {
                script {
                    withCredentials([
                        string(credentialsId: 'ROLE_ID', variable: 'ROLE_ID'),
                        string(credentialsId: 'SECRET_ID', variable: 'SECRET_ID')
                    ]) {
                        echo "Attempting to fetch Vault token from ${VAULT_ADDR}/v1/auth/approle/login"
                        // Explicitly define the command with proper JSON
                        def curlCommand = 'curl -s --request POST --data \'{"role_id":"\'"$ROLE_ID"\'","secret_id":"\'"$SECRET_ID"\'"}\' "$VAULT_ADDR/v1/auth/approle/login" 2>&1'
                        echo "Executing command: ${curlCommand.replace(ROLE_ID, '****').replace(SECRET_ID, '****')}"  # Log masked command
                        def tokenResponse = sh(script: curlCommand, returnStdout: true).trim()

                        echo "Raw Vault response: ${tokenResponse}"
                        try {
                            def tokenJson = readJSON(text: tokenResponse)
                            echo "Parsed JSON: ${tokenJson.toString()}"
                            if (!tokenJson.auth?.client_token) {
                                echo "No client_token found in response"
                                error("Failed to obtain Vault token: Authentication error - response: ${tokenResponse}")
                            } else {
                                echo "Vault token obtained successfully"
                                wrap([$class: 'MaskPasswordsBuildWrapper']) {
                                    env.VAULT_TOKEN = tokenJson.auth.client_token
                                }
                            }
                        } catch (Exception e) {
                            echo "Error parsing Vault response: ${e.message}"
                            error("Failed to obtain Vault token: Parsing error - response: ${tokenResponse}")
                        }
                    }
                }
            }
        }

            stage('Fetch Vault Token') {
                steps {
                    script {
                        withCredentials([
                            string(credentialsId: 'vault-role-id', variable: 'ROLE_ID'),
                            string(credentialsId: 'vault-secret-id', variable: 'SECRET_ID')
                        ]) {
                            echo "Attempting to fetch Vault token from ${VAULT_ADDR}/v1/auth/approle/login"
                            // Define the curl command with proper JSON syntax
                            def curlCommand = 'curl -s --request POST --data \'{"role_id":"\'"$ROLE_ID"\'","secret_id":"\'"$SECRET_ID"\'"}\' "$VAULT_ADDR/v1/auth/approle/login" 2>&1'
                            // Log the masked command
                            echo "Executing command: ${curlCommand.replace(ROLE_ID, '****').replace(SECRET_ID, '****')}"
                            def tokenResponse = sh(script: curlCommand, returnStdout: true).trim()

                            echo "Raw Vault response: ${tokenResponse}"
                            try {
                                def tokenJson = readJSON(text: tokenResponse)
                                echo "Parsed JSON: ${tokenJson.toString()}"
                                if (!tokenJson.auth?.client_token) {
                                    echo "No client_token found in response"
                                    error("Failed to obtain Vault token: Authentication error - response: ${tokenResponse}")
                                } else {
                                    echo "Vault token obtained successfully"
                                    wrap([$class: 'MaskPasswordsBuildWrapper']) {
                                        env.VAULT_TOKEN = tokenJson.auth.client_token
                                    }
                                }
                            } catch (Exception e) {
                                echo "Error parsing Vault response: ${e.message}"
                                error("Failed to obtain Vault token: Parsing error - response: ${tokenResponse}")
                            }
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
                        ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
                        -Dsonar.projectKey=derrickSh43_basic \
                        -Dsonar.organization=derricksh43 \
                        -Dsonar.host.url=${SONARQUBE_URL} \
                        -Dsonar.login=${SONAR_TOKEN}
                    """, returnStatus: true)

                    if (scanStatus != 0) {
                        def sonarIssuesRaw = sh(script: """
                            curl -s -u ${SONAR_TOKEN}: \
                            "${SONARQUBE_URL}/api/issues/search?componentKeys=derrickSh43_basic&severities=BLOCKER,CRITICAL&statuses=OPEN" | jq -r '.issues[]'
                        """, returnStdout: true).trim()

                        if (sonarIssuesRaw) {
                            def sonarIssues = readJSON(text: "[${sonarIssuesRaw.split('\n').join(',')}]")
                            if (sonarIssues.size() > 0) {
                                def issueDetails = sonarIssues.collect { issue ->
                                    def filePath = issue.component.split(':').last()
                                    def line = issue.line ?: 'N/A'
                                    def snippet = getCodeSnippet(filePath, line)
                                    "Issue: ${issue.message}\nFile: ${filePath}\nLine: ${line}\nSnippet:\n${snippet ?: 'Not available'}"
                                }.join('\n\n')
                                createJiraTicket("SonarQube Security Vulnerabilities Detected", issueDetails)
                                env.SCAN_FAILED = "true"
                            }
                        }
                    }
                }
            }
        }

        stage('Snyk Security Scan') {
            steps {
                script {
                    sh 'export SNYK_TOKEN=${SNYK_TOKEN}'
                    sh "snyk iac test --json --severity-threshold=low > snyk-results.json || true"
                    def snykIssuesList = readJSON(file: "snyk-results.json").infrastructureAsCodeIssues
                    if (snykIssuesList?.size() > 0) {
                        def issueDetails = snykIssuesList.collect { issue ->
                            def filePath = issue.filePath ?: 'N/A'
                            def line = issue.lineNumber ?: 'N/A'
                            def snippet = getCodeSnippet(filePath, line)
                            "Issue: ${issue.title}\nSeverity: ${issue.severity}\nFile: ${filePath}\nLine: ${line}\nImpact: ${issue.impact}\nResolution: ${issue.resolution}\nSnippet:\n${snippet ?: 'Not available'}"
                        }.join('\n\n')
                        createJiraTicket("Snyk IaC Security Issues Detected", issueDetails)
                        env.SCAN_FAILED = "true"
                    } else {
                        echo "No Snyk issues detected."
                    }
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
                    jfrog rt upload "dist/*.zip" "${ARTIFACTORY_REPO}/${NAMESPACE}/${MODULE_NAME}/${VERSION}/" \
                    --url="${ARTIFACTORY_URL}" --user="${ARTIFACTORY_USER}" --apikey="${ARTIFACTORY_API_KEY}"
                """
            }
        }

        stage('JFrog Xray Scan') {
            steps {
                script {
                    sh """
                        jfrog rt bs \
                        --url="${ARTIFACTORY_URL}" \
                        --user="${ARTIFACTORY_USER}" \
                        --apikey="${ARTIFACTORY_API_KEY}" \
                        "${ARTIFACTORY_REPO}/${NAMESPACE}/${MODULE_NAME}/${VERSION}/" > xray-scan.json || true
                    """
                    def xrayIssues = readJSON(file: "xray-scan.json").violations
                    if (xrayIssues?.size() > 0) {
                        def issueDetails = xrayIssues.collect { issue ->
                            "Issue: ${issue.summary}\nSeverity: ${issue.severity}\nDescription: ${issue.description}\nCVE: ${issue.cve ?: 'N/A'}"
                        }.join('\n\n')
                        createJiraTicket("JFrog Xray Security Violations Detected", issueDetails)
                        env.SCAN_FAILED = "true"
                    } else {
                        echo "No JFrog Xray violations detected."
                    }
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