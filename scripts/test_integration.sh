#!/bin/bash
set -e

# Integration test script using LocalStack

echo "Running integration tests with LocalStack"
echo "==========================================="

# Check if LocalStack is running
if ! docker ps | grep -q localstack; then
    echo "Starting LocalStack..."
    docker run -d --name localstack \
        -p 4566:4566 \
        -e SERVICES=s3,lambda,sqs,secretsmanager,cloudwatch \
        localstack/localstack:latest
    
    echo "Waiting for LocalStack to be ready..."
    sleep 10
fi

export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

echo "LocalStack ready"

# Create test resources
echo "Creating test S3 bucket..."
aws --endpoint-url=$AWS_ENDPOINT_URL s3 mb s3://test-bucket

echo "Creating test secret..."
aws --endpoint-url=$AWS_ENDPOINT_URL secretsmanager create-secret \
    --name test-slack-webhook \
    --secret-string '{"webhook_url":"http://localhost:8080/webhook"}'

echo "Creating test SQS queue..."
aws --endpoint-url=$AWS_ENDPOINT_URL sqs create-queue --queue-name test-queue

echo "Test resources created"

# Run Python tests
echo "Running Python unit tests..."
cd src
pytest tests/ -v

echo "All tests passed"

# Cleanup
echo "Cleaning up..."
docker stop localstack
docker rm localstack

echo "Integration tests complete"
