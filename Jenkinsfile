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
                bash '''#!/bin/bash
                terraform -v
                '''
            }
        }
    }
}