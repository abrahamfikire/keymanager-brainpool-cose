# MOSIP Kernel Keymanager Service

This is a Java implementation of MOSIP's kernel-keymanager-service with enhanced CBOR/COSE signing and verification capabilities for MOSIP QR code specifications.

## Features

- **CBOR/COSE Signing**: Support for signing CBOR-encoded data using COSE_Sign1
- **Signature Verification**: Verification of COSE_Sign1 signatures
- **Multiple Curve Support**: Support for various elliptic curves including Brainpool and SECP256K1
- **HSM Integration**: Integration with Hardware Security Modules
- **REST API**: RESTful endpoints for signing and verification operations

## Key Components

### COSESign1Util
Utility class for CBOR/COSE operations:
- `sign()`: Signs CBOR payloads using COSE_Sign1
- `verify()`: Verifies COSE_Sign1 signatures
- `jsonToBytes()`: Converts JSON to CBOR bytes

### SignatureServiceImpl
Main service implementation with methods:
- `coseSign1()`: Creates COSE_Sign1 signatures
- `coseVerify1()`: Verifies COSE_Sign1 signatures
- `jwtSign()`: JWT signing capabilities
- `jwtVerify()`: JWT verification

## API Endpoints

- `POST /signature/cose/sign1`: Sign CBOR data with COSE_Sign1
- `POST /signature/cose/verify1`: Verify COSE_Sign1 signatures

## Dependencies

- COSE-JAVA library for CBOR/COSE operations
- BouncyCastle for cryptographic operations
- Spring Boot for REST API
- MOSIP kernel components

## Usage

### Signing CBOR Data
```bash
curl -X POST http://localhost:8080/signature/cose/sign1 \
  -H "Content-Type: application/json" \
  -d '{
    "dataToSign": "base64EncodedJsonData",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }'
```

### Verifying COSE_Sign1
```bash
curl -X POST http://localhost:8080/signature/cose/verify1 \
  -H "Content-Type: application/json" \
  -d '{
    "coseSign1Data": "base64EncodedCoseSign1",
    "actualData": "base64EncodedOriginalData",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }'
```

## Configuration

The service supports various configuration options through application properties:
- Key management settings
- Cryptographic algorithm preferences
- HSM provider configurations

## License

This project is part of the MOSIP (Modular Open Source Identity Platform) ecosystem.
