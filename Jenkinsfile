pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git branch: 'jenkins',
                    url: 'git@github.com:oleksandrmelnychenko/Ecliptix-Web-Server.git',
                    credentialsId: 'ecliptix-memberships_github'
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    def tag = env.BUILD_NUMBER ?: 'latest'
                    docker.build("ecliptix-memberships:${tag}")
                }
            }
        }
    }
}
