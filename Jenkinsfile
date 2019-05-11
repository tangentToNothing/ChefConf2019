pipeline {
    agent {
        label 'master'
    }
    environment {
        test = "None"
    }
    stages {
        stage('Build') {
            steps {
                echo "Test"
                sh '''#!/bin/bash
                terraform -v
                '''
            }
        }
    }
}