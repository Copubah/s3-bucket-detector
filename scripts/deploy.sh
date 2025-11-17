#!/bin/bash
set -e

# S3 Bucket Detector Deployment Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}S3 Bucket Detector Deployment${NC}"
echo "=================================="

# Check prerequisites
echo -e "\n${YELLOW}Checking prerequisites...${NC}"

if ! command -v terraform &> /dev/null; then
    echo -e "${RED}ERROR: Terraform not found. Please install Terraform 1.5.0+${NC}"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo -e "${RED}ERROR: AWS CLI not found. Please install AWS CLI${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python 3 not found. Please install Python 3.11+${NC}"
    exit 1
fi

echo -e "${GREEN}All prerequisites met${NC}"

# Build Lambda package
echo -e "\n${YELLOW}Building Lambda deployment package...${NC}"
cd "$PROJECT_ROOT/src"

# Create package directory
rm -rf package lambda.zip
mkdir -p package

# Install dependencies
pip install -r requirements.txt -t package/ --quiet

# Copy source files
cp *.py package/

# Create zip
cd package
zip -r ../lambda.zip . > /dev/null
cd ..

PACKAGE_SIZE=$(du -h lambda.zip | cut -f1)
echo -e "${GREEN}Lambda package built: ${PACKAGE_SIZE}${NC}"

# Upload to S3
echo -e "\n${YELLOW}Uploading Lambda package to S3...${NC}"

if [ -z "$LAMBDA_BUCKET_NAME" ]; then
    echo -e "${RED}ERROR: LAMBDA_BUCKET_NAME environment variable not set${NC}"
    exit 1
fi

aws s3 cp lambda.zip "s3://${LAMBDA_BUCKET_NAME}/lambda/s3-detector.zip"
echo -e "${GREEN}Uploaded to s3://${LAMBDA_BUCKET_NAME}/lambda/s3-detector.zip${NC}"

# Deploy Terraform
echo -e "\n${YELLOW}Deploying infrastructure with Terraform...${NC}"
cd "$PROJECT_ROOT/terraform"

terraform init
terraform plan -out=tfplan
terraform apply tfplan

echo -e "\n${GREEN}Deployment complete${NC}"
echo -e "\nNext steps:"
echo -e "1. Set Slack webhook: aws secretsmanager put-secret-value --secret-id s3-detector-slack-webhook --secret-string '{\"webhook_url\":\"YOUR_URL\"}'"
echo -e "2. Test: aws lambda invoke --function-name s3-bucket-detector --payload '{}' response.json"
echo -e "3. Monitor: aws logs tail /aws/lambda/s3-bucket-detector --follow"
