pipeline {
    agent any
    environment {
        AWS_REGION = 'us-east-1' // e.g., "us-east-1", "us-west-2"
        SONARQUBE_URL = "https://sonarcloud.io" // e.g., "https://sonarcloud.io"
        JIRA_SITE = "https://derrickweil.atlassian.net" // e.g., "https://derrickweil.atlassian.net"
        JIRA_PROJECT = "SCRUM" // e.g., "DEVOPS", "SECURITY", "SCRUM"
        JIRA_TOKEN = credentials('JIRA_API_TOKEN') // Use Jenkins credentials
    }
}

    stages {
        stage('Set AWS Credentials') {
            steps {
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'AWS_SECRET_ACCESS_KEY' 
                ]]) {
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

                // Security Scans
        stage('Static Code Analysis (SAST)') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'SONARQUBE_TOKEN_ID', variable: 'SONAR_TOKEN')]) {
                        
                        sh 'tfsec . --format sarif --out tfsec-report.sarif'

                        def scanStatus = sh(script: '''
                            ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
                            -Dsonar.projectKey=derrickSh43_basic \
                            -Dsonar.organization=derricksh43 \
                            -Dsonar.host.url=${SONARQUBE_URL} \
                            -Dsonar.login=''' + SONAR_TOKEN + ''' \
                            -Dsonar.externalIssuesReportPaths=tfsec-report.sarif
                        ''', returnStatus: true)

                        if (scanStatus != 0) {
                            def tfsecIssues = sh(script: "jq -r '.runs[0].results[].message' tfsec-report.sarif || echo 'No issues found'", returnStdout: true).trim()

                            def sonarIssues = sh(script: '''
                                curl -s -u ${SONAR_TOKEN}: \
                                "<SONARCLOUD_URL>/api/issues/search?componentKeys=derrickSh43_basic&severities=BLOCKER,CRITICAL&statuses=OPEN" | jq -r '.issues[].message' || echo "No issues found"
                            ''', returnStdout: true).trim()

                            def issueDescription = """ 
                                **SonarCloud Security Issues:**
                                ${sonarIssues}

                                **Terraform Security Issues (TFSec):**
                                ${tfsecIssues}
                            """.stripIndent()

                            createJiraTicket("Security Vulnerabilities Detected", issueDescription)
                            error("SonarQube found security vulnerabilities in Terraform files!")
                        }
                    }
                }
            }



        stage('Snyk Security Scan') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'SNYK_AUTH_TOKEN_ID', variable: 'SNYK_TOKEN')]) {
                        sh "snyk auth ${SNYK_TOKEN}"
                        
                        def snykIssues = sh(script: "snyk iac test --json || echo '{}'", returnStdout: true).trim()
                        
                        sh "snyk monitor || echo 'No supported files found, monitoring skipped.'"

                        def snykFindings = sh(script: "echo '${snykIssues}' | jq -r '.infrastructureAsCodeIssues[]?.message' || echo 'No issues found'", returnStdout: true).trim()

                        if (snykFindings != "No issues found") {
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


        stage('Aqua Trivy Security Scan') {
                    steps {
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
                sh '''
                terraform init
                '''
            }
        }


        stage('Plan Terraform') {
            steps {
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
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
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
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
        withCredentials([string(credentialsId: 'JIRA_API_TOKEN')]) {
            jiraNewIssue site: JIRA_SITE,
                         projectKey: JIRA_PROJECT,
                         issueType: "Bug",
                         summary: issueTitle,
                         description: issueDescription,
                         priority: "High"
        }
    }
}