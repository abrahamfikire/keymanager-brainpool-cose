#!/usr/bin/env python3
"""
Test script to demonstrate enhanced CBOR logging with various scenarios
"""

import requests
import json

# Test server URL
BASE_URL = "http://localhost:8088/v1/keymanager"

def test_valid_cbor():
    """Test with valid CBOR data"""
    print("=" * 60)
    print("TESTING VALID CBOR DATA")
    print("=" * 60)
    
    # Valid CBOR hex string
    valid_hex = "a3041a499602d20769746573742d646174611900a9a504684a616e6520446f65086831393930303031303109020c6b30393837363534333231300d6a576f6e6465726c616e64"
    
    payload = {
        "id": "test-valid-cbor",
        "metadata": {},
        "request": {
            "applicationId": "ID_REPO",
            "dataToSign": valid_hex,
            "referenceId": "EC_SECP256R1_SIGN"
        },
        "requesttime": "2018-12-10T06:12:52.994Z",
        "version": "1.0"
    }
    
    print(f"Request payload:")
    print(f"  ID: {payload['id']}")
    print(f"  ApplicationId: {payload['request']['applicationId']}")
    print(f"  ReferenceId: {payload['request']['referenceId']}")
    print(f"  DataToSign length: {len(payload['request']['dataToSign'])} characters")
    print(f"  DataToSign preview: {payload['request']['dataToSign'][:20]}...{payload['request']['dataToSign'][-20:]}")
    
    try:
        response = requests.post(f"{BASE_URL}/cborSign", 
                               headers={"Content-Type": "application/json"},
                               json=payload)
        
        print(f"\nResponse Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            if result.get('response', {}).get('cborSignedData'):
                print(f"SUCCESS: CBOR signing completed")
                print(f"Output length: {len(result['response']['cborSignedData'])} characters")
            else:
                print(f"FAILED: No signed data returned")
                print(f"Response: {json.dumps(result, indent=2)}")
        else:
            print(f"ERROR: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"EXCEPTION: {e}")

def test_invalid_cbor():
    """Test with invalid CBOR data (the original problematic hex)"""
    print("\n" + "=" * 60)
    print("TESTING INVALID CBOR DATA")
    print("=" * 60)
    
    # Invalid CBOR hex string (contains binary data in text string)
    invalid_hex = "a3041a66b1e3b507782461626364313233342d353637382d393061622d636465662d313233343536373839306162a90478684a616e6520446f65087808313939303031303109020c6b30393837363534333231300d6a576f6e6465726c616e64613e81a200584052494646020300005745425056503820f6020000b01c009d012aa000c8003f69aacb5bb3bfbd2babd35aa3f02d09672d800aa7c3be99c9521514741d9446a41c1ce47180e652c8d60370a232a534b2bc653e0c075dd642b47780c652cfe1a11c59dbb87123ed9b4447577829d771d0cb7e383da6e24104fd32c24450c29a232749a3d1ef621211a00a6a99e1d92a4eaa2055179a8afb6e70c677a9edc7e09102fbf7368344fe382e8111ba4e39e7a5740155e0ee2144569dbb1a92035b8f42e0126416238df9b0d914f2159e28f050b501329f7713312be0c19ab032b4170fc0f634e6ed1f7be6fb379823b55e2ff8a6d2b05e40bc8db458c649fb375ed2ef84700000feea78110fde6f759e8787a50b0d1f3f3a0548a84b947cc2c16380dc7106974822e09b5ca0afd13547c984a38d407be05feeb8a37270e0ea19ef0f9bef7ea1d8788938f6d0780d7326624205a395cad3131a4ba060cd122bf1396eb94b0c7e36ff92b585af5a8ab3043d45c08f151876e31217a5835724e193018b6982dea57d20057f2fa579bf44bebf000296cb23436655d6371cfb1ebd7dc8f6fec5e523ea83af0031dc896f315508dfb38d373017d13bc820450ded245a65f42014a9cf09e00337acc4be1721891e5478c195e4e31d1d0d264357d168f6e2b6cddb85aab2d52450134f7d3e08c6e72fba4ad1610ec2d36c55e6aa62394440a10b712d622e4a4a28b82f7f0a347f7b51b3417ef6949d8447d7f488a421a03119fd2550d1dd62b3c368640a7cd64051115273ec1d09921dd19e2dc0c29afd2d74991de2c9aaecc6e33607ab0278a0913f6730410582564d6b9d68d5eb2c1b67eec36034462a8a3ffc0951f27b8223da9185e5214003fe04f7479acc72a503d18482bea4849e9d824707a7bc5440db095feb3d9b59d2fdf7991ced527dfa379c5ae0b78c6a291a1508d8dd84df656262d7bea50ea0c2fbcb71edd8748c45c568ba079d355e6f1ae095f62b9d679a7925e007e2d0562a8578b2c6c090eb40249c27aa25f6469e8da60a8d6450f062ccb3406eeb0517869d6b2ce97462ca0ec566a8bfbc5a63bd9519edf6180000"
    
    payload = {
        "id": "test-invalid-cbor",
        "metadata": {},
        "request": {
            "applicationId": "ID_REPO",
            "dataToSign": invalid_hex,
            "referenceId": "EC_SECP256R1_SIGN"
        },
        "requesttime": "2018-12-10T06:12:52.994Z",
        "version": "1.0"
    }
    
    print(f"Request payload:")
    print(f"  ID: {payload['id']}")
    print(f"  ApplicationId: {payload['request']['applicationId']}")
    print(f"  ReferenceId: {payload['request']['referenceId']}")
    print(f"  DataToSign length: {len(payload['request']['dataToSign'])} characters")
    print(f"  DataToSign preview: {payload['request']['dataToSign'][:20]}...{payload['request']['dataToSign'][-20:]}")
    
    try:
        response = requests.post(f"{BASE_URL}/cborSign", 
                               headers={"Content-Type": "application/json"},
                               json=payload)
        
        print(f"\nResponse Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            if result.get('response', {}).get('cborSignedData'):
                print(f"SUCCESS: CBOR signing completed")
                print(f"Output length: {len(result['response']['cborSignedData'])} characters")
            else:
                print(f"FAILED: No signed data returned")
                print(f"Response: {json.dumps(result, indent=2)}")
        else:
            print(f"ERROR: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"EXCEPTION: {e}")

def test_odd_length_hex():
    """Test with odd-length hex string"""
    print("\n" + "=" * 60)
    print("TESTING ODD-LENGTH HEX STRING")
    print("=" * 60)
    
    # Odd-length hex string
    odd_hex = "a3041a499602d20769746573742d646174611900a9a504684a616e6520446f65086831393930303031303109020c6b30393837363534333231300d6a576f6e6465726c616e6"  # Missing last character
    
    payload = {
        "id": "test-odd-length-hex",
        "metadata": {},
        "request": {
            "applicationId": "ID_REPO",
            "dataToSign": odd_hex,
            "referenceId": "EC_SECP256R1_SIGN"
        },
        "requesttime": "2018-12-10T06:12:52.994Z",
        "version": "1.0"
    }
    
    print(f"Request payload:")
    print(f"  ID: {payload['id']}")
    print(f"  DataToSign length: {len(payload['request']['dataToSign'])} characters (ODD)")
    print(f"  DataToSign preview: {payload['request']['dataToSign'][:20]}...{payload['request']['dataToSign'][-20:]}")
    
    try:
        response = requests.post(f"{BASE_URL}/cborSign", 
                               headers={"Content-Type": "application/json"},
                               json=payload)
        
        print(f"\nResponse Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            if result.get('response', {}).get('cborSignedData'):
                print(f"SUCCESS: CBOR signing completed")
                print(f"Output length: {len(result['response']['cborSignedData'])} characters")
            else:
                print(f"FAILED: No signed data returned")
                print(f"Response: {json.dumps(result, indent=2)}")
        else:
            print(f"ERROR: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"EXCEPTION: {e}")

def test_null_data():
    """Test with null data"""
    print("\n" + "=" * 60)
    print("TESTING NULL DATA")
    print("=" * 60)
    
    payload = {
        "id": "test-null-data",
        "metadata": {},
        "request": {
            "applicationId": "ID_REPO",
            "dataToSign": None,
            "referenceId": "EC_SECP256R1_SIGN"
        },
        "requesttime": "2018-12-10T06:12:52.994Z",
        "version": "1.0"
    }
    
    print(f"Request payload:")
    print(f"  ID: {payload['id']}")
    print(f"  DataToSign: {payload['request']['dataToSign']}")
    
    try:
        response = requests.post(f"{BASE_URL}/cborSign", 
                               headers={"Content-Type": "application/json"},
                               json=payload)
        
        print(f"\nResponse Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            if result.get('response', {}).get('cborSignedData'):
                print(f"SUCCESS: CBOR signing completed")
                print(f"Output length: {len(result['response']['cborSignedData'])} characters")
            else:
                print(f"FAILED: No signed data returned")
                print(f"Response: {json.dumps(result, indent=2)}")
        else:
            print(f"ERROR: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"EXCEPTION: {e}")

if __name__ == "__main__":
    print("CBOR Signing Test Script with Enhanced Logging")
    print("This script tests various scenarios to demonstrate the enhanced logging")
    print("Make sure the server is running on http://localhost:8088")
    print()
    
    # Run all tests
    test_valid_cbor()
    test_invalid_cbor()
    test_odd_length_hex()
    test_null_data()
    
    print("\n" + "=" * 60)
    print("TESTING COMPLETED")
    print("=" * 60)
    print("Check the server logs for detailed debugging information:")
    print("- Look for CBOR_SIGN_CONTROLLER and CBOR_SIGN log entries")
    print("- Check for specific error messages and byte analysis")
    print("- Verify that problematic bytes are logged around error offsets") 