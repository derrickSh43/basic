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
                    withCredentials([string(credentialsId: 'SONARQUBE_TOKEN_ID', variable: 'SONAR_TOKEN')]) {
                        
                        // Use Trivy instead of tfsec
                        sh 'trivy config -f sarif . | tee trivy-report.sarif'

                        def scanStatus = sh(script: '''
                            ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
                            -Dsonar.projectKey=derrickSh43_basic \
                            -Dsonar.organization=derricksh43 \
                            -Dsonar.host.url=${SONARQUBE_URL} \
                            -Dsonar.login=${SONAR_TOKEN} \
                            -Dsonar.externalIssuesReportPaths=trivy-report.sarif
                        ''', returnStatus: true)

                        if (scanStatus != 0) {
                            def trivyIssues = sh(script: "jq -r '.Results[].Misconfigurations[]?.Description' trivy-report.sarif || echo 'No issues found'", returnStdout: true).trim()

                            def sonarIssues = sh(script: '''
                                curl -s -u ${SONAR_TOKEN}: \
                                "${SONARQUBE_URL}/api/issues/search?componentKeys=derrickSh43_basic&severities=BLOCKER,CRITICAL&statuses=OPEN" | jq -r '.issues[].message' || echo "No issues found"
                            ''', returnStdout: true).trim()

                            if (!sonarIssues.contains("No issues found") || !trivyIssues.contains("No issues found")) {
                                def issueDescription = """ 
                                    **SonarCloud Security Issues:**
                                    ${sonarIssues}

                                    **Terraform Security Issues (Trivy):**
                                    ${trivyIssues}
                                """.stripIndent()

                                createJiraTicket("Security Vulnerabilities Detected", issueDescription)
                                error("SonarQube and/or Trivy found security vulnerabilities!")
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
                        sh 'echo $SNYK_TOKEN | snyk auth'
                        
                        def snykIssues = sh(script: "snyk iac test --json || echo '{\"infrastructureAsCodeIssues\": []}'", returnStdout: true).trim()

                        sh "snyk monitor || echo 'No supported files found, monitoring skipped.'"

                        def snykFindings = sh(script: "echo '${snykIssues}' | jq -r '.infrastructureAsCodeIssues | if length > 0 then .[].message else \"No issues found\" end'", returnStdout: true).trim()


                        if (!snykFindings.contains("No issues found")) {

                            def issueDescription = """ 
                                **Snyk Security Scan Found Issues:**
                                ${snykFindings}
                            """.stripIndent()
                            
                            createJiraTicket("Snyk Security Vulnerabilities Detected", issueDescription)
                            error("Snyk found security vulnerabilities in Terraform files!")
                        }
                    }
                }
            }
        }

        stage('Aqua Trivy Security Scan') {
            steps {
                script {
                    def trivyScanStatus = sh(script: '''
                        trivy iac --format json --output trivy-report.json .
                    ''', returnStatus: true)

                    def trivyIssues = sh(script: '''
                        jq -r '.Results[].Misconfigurations[]?.Description' trivy-report.json || echo "No issues found"
                    ''', returnStdout: true).trim()

                    if (trivyScanStatus != 0 && trivyIssues != "No issues found") {
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

// Jira function using withCredentials inside
def createJiraTicket(String issueTitle, String issueDescription) {
    script {
        withCredentials([string(credentialsId: 'JIRA_API_TOKEN', variable: 'JIRA_TOKEN')]) {
            jiraNewIssue site: JIRA_SITE,
                         projectKey: JIRA_PROJECT,
                         issueType: "Bug",
                         summary: issueTitle,
                         description: issueDescription,
                         priority: "High"
        }
    }
}
