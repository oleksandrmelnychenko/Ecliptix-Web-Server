pipeline { 
    agent any
    
    environment {
        AWS_DEFAULT_REGION = "eu-central-1"
        AWS_ACCOUNT_ID = "020498483284"
        ECR_REPO = "ecliptix/memberships"
        IMAGE_TAG = "lts"
        CLUSTER_NAME = "ecliptix-production"
        SERVICE_NAME = "ecliptix-memberships"
        TASK_DEFINITION = "ecliptix-memberships"
        AWS_CREDENTIALS = "aws-creds"
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    url: 'git@github.com:oleksandrmelnychenko/Ecliptix-Web-Server.git',
                    credentialsId: 'github-ssh-key'
            }
        }
    
        stage('Build Docker Image') {
            steps {
                sh """
                    set -e
                    
                    if ! sudo systemctl is-active --quiet docker; then
                      sudo systemctl start docker || true
                    fi
                    for i in {1..10}; do
                      docker info >/dev/null 2>&1 && break
                      echo "[INFO] Waiting for Docker daemon..."
                      sleep 2
                    done
                    if docker buildx ls | grep -q 'mybuilder'; then
                      echo "[INFO] Using existing builder 'mybuilder'"
                      docker buildx use mybuilder
                    else
                      echo "[INFO] Creating builder 'mybuilder'"
                      docker buildx create --name mybuilder --use
                    fi
                    
                    docker buildx inspect --bootstrap     
                                            
                    docker buildx build \
                      --platform=linux/amd64 \
                      --build-arg DOTNET_CLI_NUM_THREADS=4 \
                      -t ecliptix-membership:lts \
                      -f Ecliptix.Core/Dockerfile .
                """
            }
        }

        stage('Push to ECR') {
            steps {
                withAWS(credentials: "${AWS_CREDENTIALS}", region: "${AWS_DEFAULT_REGION}") {
                    sh """
                    aws ecr get-login-password --region ${AWS_DEFAULT_REGION} \
                        | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com

                    docker tag ${ECR_REPO}:${IMAGE_TAG} ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}
                    docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}
                    """
                }
            }
        }

        stage('Update ECS Task Definition') {
            steps {
                withAWS(credentials: "${AWS_CREDENTIALS}", region: "${AWS_DEFAULT_REGION}") {
                    sh """
                    aws ecs describe-task-definition \
                      --task-definition ${TASK_DEFINITION} \
                      --query 'taskDefinition' > task-def.json
                
                    jq '{
                      family: .family,
                      taskRoleArn: .taskRoleArn,
                      executionRoleArn: .executionRoleArn,
                      networkMode: .networkMode,
                      containerDefinitions: (.containerDefinitions | map(.image = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}")),
                      volumes: .volumes,
                      requiresCompatibilities: .requiresCompatibilities,
                      cpu: .cpu,
                      memory: .memory,
                      runtimePlatform: .runtimePlatform,
                      enableFaultInjection: .enableFaultInjection
                    } | with_entries(select(.value != null))' task-def.json > new-task-def.json
                
                    aws ecs register-task-definition --cli-input-json file://new-task-def.json
                    """
                }
            }
        }

        stage('Deploy to ECS') {
            steps {
                withAWS(credentials: "${AWS_CREDENTIALS}", region: "${AWS_DEFAULT_REGION}") {
                    sh """
                    NEW_REVISION=\$(aws ecs describe-task-definition \
                      --task-definition ${TASK_DEFINITION} \
                      --query 'taskDefinition.revision' --output text)

                    aws ecs update-service \
                      --cluster ${CLUSTER_NAME} \
                      --service ${SERVICE_NAME} \
                      --task-definition ${TASK_DEFINITION}:\$NEW_REVISION
                    """
                }
            }
        }
    }
}
