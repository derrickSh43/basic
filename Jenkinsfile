pipeline {
    agent any

    environment {
        AWS_REGION = 'us-east-1'
        SONARQUBE_URL = "https://sonarcloud.io"
        JIRA_SITE = "https://derrickweil.atlassian.net"
        JIRA_PROJECT = "SCRUM"
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

                        // Run Snyk scan and capture exit status
                        def snykScanStatus = sh(script: "snyk iac test --json --severity-threshold=low", returnStatus: true)
                        echo "Snyk Scan Status: ${snykScanStatus}"

                        // If Snyk detects vulnerabilities, extract issues
                        if (snykScanStatus != 0) {
                            echo "Snyk found security vulnerabilities! Extracting issues..."

                            def snykFindings = sh(script: """
                                snyk iac test --json --severity-threshold=low | jq -r '[.infrastructureAsCodeIssues[]?.message] | join("\\n")' || echo 'No issues found'
                            """, returnStdout: true).trim()

                            echo "Snyk Findings: ${snykFindings}"

                            // If issues were found, create a Jira ticket
                            if (!snykFindings.contains("No issues found") && snykFindings.trim()) {
                                echo "Creating Jira Ticket for Snyk vulnerabilities..."
                                createJiraTicket("Snyk Security Vulnerabilities Detected", snykFindings)
                            } else {
                                echo "No actionable security vulnerabilities detected by Snyk."
                            }

                            // Stop the pipeline due to vulnerabilities
                            error("Snyk found security vulnerabilities! Stopping pipeline.")
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
        withCredentials([string(credentialsId: 'JIRA_API_TOKEN', variable: 'JIRA_TOKEN'),
                         string(credentialsId: 'JIRA_EMAIL', variable: 'JIRA_USER')]) {

            if (!issueDescription?.trim()) {
                echo "Skipping Jira ticket creation: Issue description is empty."
                return
            }

            def formattedDescription = issueDescription.replaceAll('"', '\\"')

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

            def response = sh(script: """
                curl -X POST "https://derrickweil.atlassian.net/rest/api/3/issue" \
                --user "$JIRA_USER:$JIRA_TOKEN" \
                -H "Content-Type: application/json" \
                --data '${jiraPayload}'
            """, returnStdout: true).trim()

            echo "Jira Response: ${response}"

            if (!response.contains('"key"')) {
                error("Jira ticket creation failed! Response: ${response}")
            }
        }
    }
}





