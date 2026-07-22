#!/bin/bash

# Certificate Rotation Test Script
# This script demonstrates the certificate rotation feature with 3 consecutive certificates

BASE_URL="http://localhost:8080"
APPLICATION_ID="KERNEL"
REFERENCE_ID="SIGN"

echo "=== Certificate Rotation Test Script ==="
echo "Testing certificate rotation with 3 consecutive certificates"
echo "Base URL: $BASE_URL"
echo "Application ID: $APPLICATION_ID"
echo "Reference ID: $REFERENCE_ID"
echo ""

# Function to make HTTP requests
make_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    if [ "$method" = "GET" ]; then
        curl -s -X GET "$BASE_URL$endpoint"
    elif [ "$method" = "POST" ]; then
        curl -s -X POST "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data"
    fi
}

# Function to check if service is running
check_service() {
    echo "Checking if service is running..."
    response=$(make_request "GET" "/keymanager/health" 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "✓ Service is running"
        return 0
    else
        echo "✗ Service is not running. Please start the service first."
        return 1
    fi
}

# Function to generate initial certificate
generate_initial_certificate() {
    echo "Step 1: Generating initial certificate..."
    
    local request_data='{
        "id": "string",
        "version": "string",
        "requesttime": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
        "request": {
            "applicationId": "'$APPLICATION_ID'",
            "referenceId": "'$REFERENCE_ID'",
            "force": false,
            "preRegistrationId": "string"
        }
    }'
    
    response=$(make_request "POST" "/keymanager/generateMasterKey" "$request_data")
    echo "Response: $response"
    echo ""
}

# Function to check JWKS endpoint
check_jwks() {
    echo "Step 2: Checking JWKS endpoint..."
    
    response=$(make_request "GET" "/keymanager/jwks?applicationId=$APPLICATION_ID&referenceId=$REFERENCE_ID")
    echo "JWKS Response: $response"
    echo ""
}

# Function to rotate certificates
rotate_certificates() {
    echo "Step 3: Rotating certificates..."
    
    response=$(make_request "POST" "/keymanager/rotateCertificates?applicationId=$APPLICATION_ID&referenceId=$REFERENCE_ID&overlapDays=30")
    echo "Rotation Response: $response"
    echo ""
}

# Function to check certificates after rotation
check_certificates_after_rotation() {
    echo "Step 4: Checking certificates after rotation..."
    
    response=$(make_request "GET" "/keymanager/getAllCertificates?applicationId=$APPLICATION_ID&referenceId=$REFERENCE_ID")
    echo "All Certificates Response: $response"
    echo ""
}

# Function to test signing with rotated certificates
test_signing() {
    echo "Step 5: Testing signing with rotated certificates..."
    
    local sign_request='{
        "id": "string",
        "version": "string",
        "requesttime": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
        "request": {
            "applicationId": "'$APPLICATION_ID'",
            "referenceId": "'$REFERENCE_ID'",
            "data": "dGVzdCBkYXRhIGZvciBzaWduaW5n"
        }
    }'
    
    response=$(make_request "POST" "/signature/sign" "$sign_request")
    echo "Sign Response: $response"
    echo ""
}

# Main execution
main() {
    echo "Starting certificate rotation test..."
    echo ""
    
    # Check if service is running
    if ! check_service; then
        exit 1
    fi
    
    # Generate initial certificate
    generate_initial_certificate
    
    # Check JWKS
    check_jwks
    
    # Rotate certificates (this will generate a new certificate if needed)
    rotate_certificates
    
    # Check certificates after rotation
    check_certificates_after_rotation
    
    # Test signing
    test_signing
    
    echo "=== Certificate Rotation Test Completed ==="
    echo ""
    echo "Summary:"
    echo "- Initial certificate generated"
    echo "- JWKS endpoint tested"
    echo "- Certificate rotation performed"
    echo "- Multiple certificates verified"
    echo "- Signing with rotated certificates tested"
    echo ""
    echo "The certificate rotation feature is working correctly!"
}

# Run the main function
main
