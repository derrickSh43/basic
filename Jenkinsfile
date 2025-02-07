pipeline {
    agent any

    environment {
        AWS_REGION = 'us-east-1'
        SONARQUBE_URL = "https://sonarcloud.io"
        JIRA_SITE = "https://derrickweil.atlassian.net"
        JIRA_PROJECT = "JENKINS"
    }

    stages {
        stage('Set AWS Credentials') {
            steps {
                withCredentials([aws(credentialsId: 'AWS_SECRET_ACCESS_KEY', accessKeyVariable: 'AWS_ACCESS_KEY_ID', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh '''
                    echo "AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
                    aws sts get-caller-identity
                    '''
                }
            }
        }

        stage('Checkout Code') {
            steps {
                git branch: 'main', url: 'https://github.com/derrickSh43/basic'
            }
        }
        stage('Test Jira Ticket Creation') {
            steps {
                script {
                    echo "Testing Jira ticket creation from Jenkins pipeline..."
                    createJiraTicket("Jenkins Pipeline Test", "This is a test issue created from Jenkins to validate Jira integration.")
                }
            }
        }

        stage('Static Code Analysis (SAST)') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'SONARQUBE_TOKEN_ID', variable: 'SONAR_TOKEN')]) {

                        // Run SonarQube Scan
                        def scanStatus = sh(script: '''
                            ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
                            -Dsonar.projectKey=derrickSh43_basic \
                            -Dsonar.organization=derricksh43 \
                            -Dsonar.host.url=${SONARQUBE_URL} \
                            -Dsonar.login=${SONAR_TOKEN}
                        ''', returnStatus: true)

                        if (scanStatus != 0) {

                            def sonarIssues = sh(script: '''
                                curl -s -u ${SONAR_TOKEN}: \
                                "${SONARQUBE_URL}/api/issues/search?componentKeys=derrickSh43_basic&severities=BLOCKER,CRITICAL&statuses=OPEN" | jq -r '.issues[].message' || echo "No issues found"
                            ''', returnStdout: true).trim()

                            if (!sonarIssues.contains("No issues found")) {
                                def issueDescription = """ 
                                    **SonarCloud Security Issues:**
                                    ${sonarIssues}
                                """.stripIndent()

                                echo "Creating Jira Ticket for SonarCloud issues..."
                                createJiraTicket("SonarQube Security Vulnerabilities Detected", issueDescription)
                                error("SonarQube found security vulnerabilities! Pipeline stopping.")
                            }
                        }
                    }
                }
            }
        }

        stage('Snyk Security Scan') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'SNYK_AUTH_TOKEN_ID', variable: 'SNYK_TOKEN')]) {
                        sh 'export SNYK_TOKEN=${SNYK_TOKEN}'

                        // Run Snyk scan and save output to a file
                        def snykScanStatus = sh(script: "snyk iac test --json --severity-threshold=low > snyk-results.json || echo 'Scan completed'", returnStatus: true)
                        echo "Snyk Scan Status: ${snykScanStatus}"

                        // Print the full JSON for debugging
                        sh "cat snyk-results.json"

                        // Extract issues as a proper JSON array
                        sh "jq -c '.infrastructureAsCodeIssues | map({title, severity, impact, resolution})' snyk-results.json > snyk-issues-parsed.json"

                        // Read the extracted JSON
                        def snykIssuesList = readJSON(file: "snyk-issues-parsed.json")

                        echo "DEBUG: Total Snyk Issues Found: ${snykIssuesList.size()}"

                        if (snykIssuesList.size() > 0) {
                            for (issue in snykIssuesList) {
                                echo "DEBUG: Processing Issue: ${issue}"

                                def issueTitle = "Snyk Issue: ${issue.title} - Severity: ${issue.severity}"
                                def issueDescription = """
                                Impact: ${issue.impact}
                                Resolution: ${issue.resolution}
                                """

                                echo "Creating Jira Ticket for: ${issueTitle}"
                                echo "Description:\n${issueDescription}"

                                // Call Jira ticket creation function
                                def jiraIssueKey = createJiraTicket(issueTitle, issueDescription)
                                echo "Jira Ticket Created: ${jiraIssueKey}"
                            }
                        } else {
                            echo "DEBUG: No issues to process."
                        }
                    }
                }
            }
        }


        stage('Aqua Trivy Security Scan') {
            steps {
                script {
                    def trivyScanStatus = sh(script: '''
                        trivy config -f json . | tee trivy-report.json
                    ''', returnStatus: true)

                    // Ensure the JSON report exists before parsing
                    if (!fileExists('trivy-report.json')) {
                        echo "Trivy report not found. Skipping analysis."
                        return
                    }

                    def trivyIssues = sh(script: '''
                        jq -r '.Results[].Misconfigurations[]?.Description // "No issues found"' trivy-report.json
                    ''', returnStdout: true).trim()

                    if (trivyScanStatus != 0 && !trivyIssues.contains("No issues found")) {
                        def issueDescription = """ 
                            **Aqua Trivy Security Issues:**
                            ${trivyIssues}
                        """.stripIndent()
                        
                        createJiraTicket("Trivy Security Vulnerabilities Detected", issueDescription)
                        error("Trivy found security vulnerabilities in Terraform files!")
                    }
                }
            }
        }
        stage('Fail Pipeline if Any Scan Fails') {
            steps {
                script {
                    if (env.SCAN_FAILED?.trim() == "true") {
                        echo "Security scans detected vulnerabilities! Stopping the pipeline."
                        error("Security vulnerabilities detected! See Jira tickets for details.")
                    } else {
                        echo "All security scans passed successfully."
                    }
                }
            }
        }


        stage('Initialize Terraform') {
            steps {
                sh 'terraform init'
            }
        }

        stage('Plan Terraform') {
            steps {
                withCredentials([aws(credentialsId: 'AWS_SECRET_ACCESS_KEY', accessKeyVariable: 'AWS_ACCESS_KEY_ID', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh '''
                    export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
                    export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
                    terraform plan -out=tfplan
                    '''
                }
            }
        }

        stage('Apply Terraform') {
            steps {
                input message: "Approve Terraform Apply?", ok: "Deploy"
                withCredentials([aws(credentialsId: 'AWS_SECRET_ACCESS_KEY', accessKeyVariable: 'AWS_ACCESS_KEY_ID', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh '''
                    export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
                    export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
                    terraform apply -auto-approve tfplan
                    '''
                }
            }
        }
    }

    post {
        success {
            echo 'Terraform deployment completed successfully!'
        }

        failure {
            echo 'Terraform deployment failed!'
        }
    }
}

def createJiraTicket(String issueTitle, String issueDescription) {
    script {
        withCredentials([
            string(credentialsId: 'JIRA_API_TOKEN', variable: 'JIRA_TOKEN'),
            string(credentialsId: 'JIRA_EMAIL', variable: 'JIRA_USER')
        ]) {
            
            def formattedDescription = issueDescription
                .replaceAll('"', '\\"')  
                .replaceAll("\n", "\\n") 
                .replaceAll("\r", "")    

            def jiraPayload = """
            {
                "fields": {
                    "project": { "key": "JENKINS" },
                    "summary": "${issueTitle}",
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "${formattedDescription}"
                                    }
                                ]
                            }
                        ]
                    },
                    "issuetype": { "name": "Bug" }
                }
            }
            """

            writeFile file: 'jira_payload.json', text: jiraPayload

            withEnv(["JIRA_CREDS=${JIRA_USER}:${JIRA_TOKEN}"]) {
                // **Step 1: Search for an existing Jira ticket securely**
                def searchQuery = URLEncoder.encode("project=JENKINS AND summary~\"${issueTitle}\" AND status != Done", "UTF-8")
                def searchResponse = sh(script: '''
                    export JIRA_CREDS
                    curl -s -u "$JIRA_CREDS" \
                    -X GET "https://derrickweil.atlassian.net/rest/api/3/search?jql=''' + searchQuery + '''" \
                    -H "Accept: application/json"
                ''', returnStdout: true).trim()

                def existingIssues = readJSON(text: searchResponse)

                if (existingIssues.issues.size() > 0) {
                    echo "Jira issue already exists: ${existingIssues.issues[0].key}. Skipping ticket creation."
                    return existingIssues.issues[0].key
                }

                echo "No existing Jira issue found. Creating a new ticket..."

                // **Step 3: Create a new Jira issue securely**
                def createResponse = sh(script: '''
                    export JIRA_CREDS
                    curl -X POST "https://derrickweil.atlassian.net/rest/api/3/issue" \
                    -u "$JIRA_CREDS" \
                    -H "Content-Type: application/json" \
                    --data @jira_payload.json
                ''', returnStdout: true).trim()

                echo "Jira Response: ${createResponse}"

                def createdIssue = readJSON(text: createResponse)

                if (!createdIssue.containsKey("key")) {
                    error("Jira ticket creation failed! Response: ${createResponse}")
                }

                return createdIssue.key
            }
        }
    }
}


