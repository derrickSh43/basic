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

        stage('Static Code Analysis (SAST)') {
            steps {
                script {
                    def scanFailed = false

                    withCredentials([string(credentialsId: 'SONARQUBE_TOKEN_ID', variable: 'SONAR_TOKEN')]) {
                        def sonarStatus = sh(script: '''
                            ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
                            -Dsonar.projectKey=derrickSh43_basic \
                            -Dsonar.organization=derricksh43 \
                            -Dsonar.host.url=${SONARQUBE_URL} \
                            -Dsonar.login=${SONAR_TOKEN}
                        ''', returnStatus: true)

                        if (sonarStatus != 0) {
                            scanFailed = true
                            echo "SonarQube scan failed!"
                        }
                    }
                }
            }
        }

        stage('Snyk Security Scan') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'SNYK_AUTH_TOKEN_ID', variable: 'SNYK_TOKEN')]) {
                        def snykScanStatus = sh(script: '''
                            snyk iac test --json > snyk-results.json || echo 'Scan completed'
                        ''', returnStatus: true)

                        if (snykScanStatus != 0) {
                            echo "Snyk found security vulnerabilities!"
                            scanFailed = true
                        }
                    }
                }
            }
        }

        stage('Aqua Trivy Security Scan') {
            steps {
                script {
                    def trivyScanStatus = sh(script: '''
                        trivy config -f json -o trivy-results.json .
                    ''', returnStatus: true)

                    if (trivyScanStatus != 0) {
                        echo "Trivy found security vulnerabilities!"
                        scanFailed = true
                    }
                }
            }
        }

        stage('Fail Pipeline if Any Scan Fails') {
            steps {
                script {
                    if (scanFailed) {
                        createJiraTicket("Security Scan Failed - Critical Issues", "One or more security scans failed. Check SonarQube, Snyk, or Trivy results.")
                        error("Security scans detected critical vulnerabilities! Failing the pipeline.")
                    }
                }
            }
        }

        stage('Initialize Terraform') {
            when {
                expression { return !scanFailed }
            }
            steps {
                sh 'terraform init'
            }
        }

        stage('Plan Terraform') {
            when {
                expression { return !scanFailed }
            }
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
            when {
                expression { return !scanFailed }
            }
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
                    "project": { "key": "${JIRA_PROJECT}" },
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
                curl -X POST "${JIRA_SITE}/rest/api/3/issue" \
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
