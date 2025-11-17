#!/bin/bash
# Build Lambda deployment package

set -e

echo "Building Lambda deployment package..."

# Clean previous build
rm -rf package lambda.zip

# Create package directory
mkdir -p package

# Install dependencies
pip install -r requirements.txt -t package/

# Copy source files
cp *.py package/

# Create zip
cd package
zip -r ../lambda.zip .
cd ..

echo "Lambda package created: lambda.zip"
ls -lh lambda.zip
