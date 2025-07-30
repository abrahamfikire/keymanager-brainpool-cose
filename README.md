# MOSIP Kernel Keymanager Service

This is a Java implementation of MOSIP's kernel-keymanager-service with enhanced CBOR/COSE signing and verification capabilities for MOSIP QR code specifications.

## Features

- **CBOR/COSE Signing**: Support for signing CBOR-encoded data using COSE_Sign1
- **Signature Verification**: Verification of COSE_Sign1 signatures
- **Multiple Curve Support**: Support for various elliptic curves including Brainpool and SECP256K1
- **HSM Integration**: Integration with Hardware Security Modules
- **REST API**: RESTful endpoints for signing and verification operations
- **Raw Message Signing**: Sign and verify arbitrary messages using ECDSA and HSM-backed keys
- **CBOR/CWT Signing**: Direct support for signing and verifying CBOR-encoded data and CWT tokens
- **Credential and Binary Data Support**: Sign and verify credentials and arbitrary binary data

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
- `signRawMessage()`: Raw ECDSA message signing
- `verifyRawMessage()`: Raw ECDSA message verification
- `cborSign()`: CBOR/CWT signing and verification
- `cborVerify()`: CBOR/CWT verification
- `signCredential()`: Credential signing
- `verifyCredential()`: Credential verification
- `signBinary()`: Binary data signing
- `verifyBinary()`: Binary data verification

## API Endpoints

### COSE/CBOR Endpoints
- `POST /signature/cose/sign1`: Sign CBOR data with COSE_Sign1
- `POST /signature/cose/verify1`: Verify COSE_Sign1 signatures
- `POST /signature/cborSign`: Sign CBOR-encoded hex string (returns signed CWT/COSE hex)
- `POST /signature/cborVerify`: Verify signed CBOR CWT/COSE hex

### Raw Message Endpoints
- `POST /signature/signRawMessage`: Sign a raw message using ECDSA
- `POST /signature/verifyRawMessage`: Verify a raw message signature using ECDSA

### Credential Endpoints
- `POST /signature/signCredential`: Sign a credential message using ECDSA
- `POST /signature/verifyCredential`: Verify a credential signature using ECDSA

### Binary Data Endpoints
- `POST /signature/signBinary`: Sign binary data using ECDSA
- `POST /signature/verifyBinary`: Verify binary data signature using ECDSA

### JWT/JWS Endpoints
- `POST /signature/jwtSign`: Sign data using JWT
- `POST /signature/jwtVerify`: Verify JWT signatures
- `POST /signature/jwsSign`: Sign data using JWS
- `POST /signature/jwsVerify`: Verify JWS signatures

### Legacy Endpoints
- `POST /signature/sign`: Legacy signing endpoint (deprecated)
- `POST /signature/validate`: Legacy validation endpoint (deprecated)
- `POST /signature/pdf/sign`: PDF signing endpoint

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

### Signing Raw Messages
```bash
curl -X POST http://localhost:8080/signature/signRawMessage \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "message": "Hello, world!",
      "applicationId": "KERNEL",
      "referenceId": "SIGN"
    }
  }'
```

### Verifying Raw Messages
```bash
curl -X POST http://localhost:8080/signature/verifyRawMessage \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "message": "Hello, world!",
      "signature": "<base64Signature>",
      "applicationId": "KERNEL",
      "referenceId": "SIGN"
    }
  }'
```

### Signing Credentials
```bash
curl -X POST http://localhost:8080/signature/signCredential \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "message": "Your credential message here",
      "applicationId": "KERNEL",
      "referenceId": "SIGN"
    }
  }'
```

### Verifying Credentials
```bash
curl -X POST http://localhost:8080/signature/verifyCredential \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "message": "Your credential message here",
      "signature": "<base64Signature>",
      "applicationId": "KERNEL",
      "referenceId": "SIGN"
    }
  }'
```

### Signing CBOR Data (Hex)
```bash
curl -X POST http://localhost:8080/signature/cborSign \
  -H "Content-Type: application/json" \
  -d '{
    "dataToSign": "<hexCborData>",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }'
```

### Verifying CBOR Signatures
```bash
curl -X POST http://localhost:8080/signature/cborVerify \
  -H "Content-Type: application/json" \
  -d '{
    "cborSignatureData": "<signedCwtHex>",
    "applicationId": "KERNEL",
    "referenceId": "SIGN"
  }'
```

### Signing Binary Data
```bash
curl -X POST http://localhost:8080/signature/signBinary \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "dataBase64": "<base64EncodedBinaryData>",
      "applicationId": "KERNEL",
      "referenceId": "SIGN"
    }
  }'
```

### Verifying Binary Data
```bash
curl -X POST http://localhost:8080/signature/verifyBinary \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "dataBase64": "<base64EncodedBinaryData>",
      "signatureBase64": "<base64EncodedSignature>",
      "applicationId": "KERNEL",
      "referenceId": "SIGN"
    }
  }'
```

## Configuration

The service supports various configuration options through application properties:
- Key management settings
- Cryptographic algorithm preferences
- HSM provider configurations
- Support for BrainpoolP256r1 and SECP256K1 curves

## License

This project is part of the MOSIP (Modular Open Source Identity Platform) ecosystem.
