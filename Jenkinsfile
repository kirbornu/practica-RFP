pipeline {
    agent any

    environment {
        REGISTRY = "10.10.20.248:5000"
        IMAGE = "pac-editor"
    }

    stages {
        stage('Клонирование') {
            steps {
                checkout scm
            }
        }

        stage('Сборка образа') {
            steps {
                sh "docker build -t ${REGISTRY}/${IMAGE}:${BUILD_NUMBER} ."
            }
        }

        stage('Пуш в Registry') {
            steps {
                sh "docker push ${REGISTRY}/${IMAGE}:${BUILD_NUMBER}"
            }
        }
    }
}
