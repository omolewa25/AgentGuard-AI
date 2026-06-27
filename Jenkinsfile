// CI pipeline for AgentGuard AI.
// - Tests run inside a python:3.12-slim container (matches the app image), split into
//   fast unit tests and full-runtime integration tests, followed by a coverage gate.
// - The Docker image build runs on the Jenkins host (needs Docker available) and is
//   gated to the main branch.
pipeline {
    agent none

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    stages {
        stage('Test') {
            agent {
                docker {
                    image 'python:3.12-slim'
                    args '-u root:root'
                }
            }
            environment {
                COVERAGE_MIN = '80'
            }
            steps {
                sh '''
                    python -m pip install --upgrade pip
                    pip install -r requirements.txt -r requirements-dev.txt
                    mkdir -p reports

                    # Fast feedback first: unit tests, then integration tests.
                    python -m pytest -m unit --no-cov --junitxml=reports/unit.xml
                    python -m pytest -m integration --no-cov --junitxml=reports/integration.xml

                    # Full suite with the coverage gate (publishes Cobertura XML).
                    python -m pytest \
                        --junitxml=reports/all.xml \
                        --cov-report=xml:reports/coverage.xml \
                        --cov-fail-under=${COVERAGE_MIN}
                '''
            }
            post {
                always {
                    junit 'reports/unit.xml, reports/integration.xml'
                    archiveArtifacts artifacts: 'reports/coverage.xml', allowEmptyArchive: true
                    // Requires the Coverage plugin; remove if not installed.
                    recordCoverage(tools: [[parser: 'COBERTURA', pattern: 'reports/coverage.xml']])
                }
            }
        }

        stage('Docker build') {
            agent any
            when {
                branch 'main'
            }
            steps {
                sh 'docker build -t agentguard-ai:${BUILD_NUMBER} -t agentguard-ai:latest .'
            }
        }
    }
}
