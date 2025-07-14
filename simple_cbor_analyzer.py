#!/usr/bin/env python3
"""
Simple CBOR/CWT Analyzer - Decode and analyze CBOR Web Token data without external dependencies
"""

import base64
import json
from datetime import datetime
import sys

def hex_to_bytes(hex_string):
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_string)

def decode_cbor_basic(data, offset=0):
    """Basic CBOR decoder for simple structures"""
    if offset >= len(data):
        return None, offset
    
    byte = data[offset]
    major_type = (byte >> 5) & 0x07
    additional_info = byte & 0x1F
    
    offset += 1
    
    # Handle different major types
    if major_type == 0:  # unsigned integer
        if additional_info < 24:
            return additional_info, offset
        elif additional_info == 24:
            if offset + 1 > len(data):
                return None, offset
            return data[offset], offset + 1
        elif additional_info == 25:
            if offset + 2 > len(data):
                return None, offset
            return int.from_bytes(data[offset:offset+2], 'big'), offset + 2
        elif additional_info == 26:
            if offset + 4 > len(data):
                return None, offset
            return int.from_bytes(data[offset:offset+4], 'big'), offset + 4
        elif additional_info == 27:
            if offset + 8 > len(data):
                return None, offset
            return int.from_bytes(data[offset:offset+8], 'big'), offset + 8
    
    elif major_type == 1:  # negative integer
        if additional_info < 24:
            return -1 - additional_info, offset
        elif additional_info == 24:
            if offset + 1 > len(data):
                return None, offset
            return -1 - data[offset], offset + 1
        elif additional_info == 25:
            if offset + 2 > len(data):
                return None, offset
            return -1 - int.from_bytes(data[offset:offset+2], 'big'), offset + 2
        elif additional_info == 26:
            if offset + 4 > len(data):
                return None, offset
            return -1 - int.from_bytes(data[offset:offset+4], 'big'), offset + 4
        elif additional_info == 27:
            if offset + 8 > len(data):
                return None, offset
            return -1 - int.from_bytes(data[offset:offset+8], 'big'), offset + 8
    
    elif major_type == 2:  # byte string
        if additional_info < 24:
            length = additional_info
        elif additional_info == 24:
            if offset + 1 > len(data):
                return None, offset
            length = data[offset]
            offset += 1
        elif additional_info == 25:
            if offset + 2 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
        elif additional_info == 26:
            if offset + 4 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+4], 'big')
            offset += 4
        elif additional_info == 27:
            if offset + 8 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+8], 'big')
            offset += 8
        
        if offset + length > len(data):
            return None, offset
        return data[offset:offset+length], offset + length
    
    elif major_type == 3:  # text string
        if additional_info < 24:
            length = additional_info
        elif additional_info == 24:
            if offset + 1 > len(data):
                return None, offset
            length = data[offset]
            offset += 1
        elif additional_info == 25:
            if offset + 2 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
        elif additional_info == 26:
            if offset + 4 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+4], 'big')
            offset += 4
        elif additional_info == 27:
            if offset + 8 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+8], 'big')
            offset += 8
        
        if offset + length > len(data):
            return None, offset
        try:
            return data[offset:offset+length].decode('utf-8'), offset + length
        except UnicodeDecodeError:
            return data[offset:offset+length], offset + length
    
    elif major_type == 4:  # array
        if additional_info < 24:
            length = additional_info
        elif additional_info == 24:
            if offset + 1 > len(data):
                return None, offset
            length = data[offset]
            offset += 1
        elif additional_info == 25:
            if offset + 2 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
        elif additional_info == 26:
            if offset + 4 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+4], 'big')
            offset += 4
        elif additional_info == 27:
            if offset + 8 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+8], 'big')
            offset += 8
        
        result = []
        for _ in range(length):
            item, offset = decode_cbor_basic(data, offset)
            if item is None:
                return None, offset
            result.append(item)
        return result, offset
    
    elif major_type == 5:  # map
        if additional_info < 24:
            length = additional_info
        elif additional_info == 24:
            if offset + 1 > len(data):
                return None, offset
            length = data[offset]
            offset += 1
        elif additional_info == 25:
            if offset + 2 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
        elif additional_info == 26:
            if offset + 4 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+4], 'big')
            offset += 4
        elif additional_info == 27:
            if offset + 8 > len(data):
                return None, offset
            length = int.from_bytes(data[offset:offset+8], 'big')
            offset += 8
        
        result = {}
        for _ in range(length):
            key, offset = decode_cbor_basic(data, offset)
            if key is None:
                return None, offset
            value, offset = decode_cbor_basic(data, offset)
            if value is None:
                return None, offset
            result[key] = value
        return result, offset
    
    return None, offset

def analyze_cwt_structure(hex_data):
    """Analyze the CWT structure from hex data"""
    print("=" * 80)
    print("CBOR/CWT DATA ANALYSIS")
    print("=" * 80)
    
    try:
        # Convert hex to bytes
        print(f"Input hex length: {len(hex_data)} characters")
        cbor_bytes = hex_to_bytes(hex_data)
        print(f"Decoded bytes length: {len(cbor_bytes)} bytes")
        
        # Decode the main CBOR structure
        cwt_data, _ = decode_cbor_basic(cbor_bytes)
        if cwt_data is None:
            print("Failed to decode CBOR data")
            return
        
        print(f"\nMain CBOR structure type: {type(cwt_data)}")
        
        if isinstance(cwt_data, list) and len(cwt_data) >= 4:
            print("\nCWT Structure (COSESign1 format):")
            print(f"  Array length: {len(cwt_data)}")
            
            # Protected header (index 0)
            protected_header = cwt_data[0]
            print(f"\n1. Protected Header (index 0):")
            print(f"   Type: {type(protected_header)}")
            if isinstance(protected_header, bytes):
                try:
                    decoded_header, _ = decode_cbor_basic(protected_header)
                    print(f"   Decoded: {decoded_header}")
                    if isinstance(decoded_header, dict):
                        for key, value in decoded_header.items():
                            print(f"     {key}: {value}")
                except Exception as e:
                    print(f"   Raw bytes: {protected_header.hex()}")
                    print(f"   Decode error: {e}")
            
            # Unprotected header (index 1)
            unprotected_header = cwt_data[1]
            print(f"\n2. Unprotected Header (index 1):")
            print(f"   Type: {type(unprotected_header)}")
            if isinstance(unprotected_header, dict):
                for key, value in unprotected_header.items():
                    print(f"     {key}: {value}")
            
            # Payload (index 2)
            payload = cwt_data[2]
            print(f"\n3. Payload (index 2):")
            print(f"   Type: {type(payload)}")
            if isinstance(payload, bytes):
                try:
                    decoded_payload, _ = decode_cbor_basic(payload)
                    print(f"   Decoded payload type: {type(decoded_payload)}")
                    if isinstance(decoded_payload, dict):
                        print("   CWT Claims:")
                        for key, value in decoded_payload.items():
                            if key == 1:  # iss (issuer)
                                print(f"     Issuer (1): {value}")
                            elif key == 4:  # exp (expiration)
                                if isinstance(value, int):
                                    exp_date = datetime.fromtimestamp(value)
                                    print(f"     Expiration (4): {value} ({exp_date})")
                                else:
                                    print(f"     Expiration (4): {value}")
                            elif key == 5:  # nbf (not before)
                                if isinstance(value, int):
                                    nbf_date = datetime.fromtimestamp(value)
                                    print(f"     Not Before (5): {value} ({nbf_date})")
                                else:
                                    print(f"     Not Before (5): {value}")
                            elif key == 6:  # iat (issued at)
                                if isinstance(value, int):
                                    iat_date = datetime.fromtimestamp(value)
                                    print(f"     Issued At (6): {value} ({iat_date})")
                                else:
                                    print(f"     Issued At (6): {value}")
                            elif key == 169:  # Custom claim 169
                                print(f"     Custom Claim 169: {len(value)} bytes")
                                try:
                                    claim169_decoded, _ = decode_cbor_basic(value)
                                    print(f"       Decoded: {claim169_decoded}")
                                except Exception as e:
                                    print(f"       Raw bytes: {value.hex()[:50]}...")
                                    print(f"       Decode error: {e}")
                            else:
                                print(f"     Claim {key}: {value}")
                    else:
                        print(f"   Raw payload: {payload.hex()[:100]}...")
                except Exception as e:
                    print(f"   Raw bytes: {payload.hex()[:100]}...")
                    print(f"   Decode error: {e}")
            
            # Signature (index 3)
            signature = cwt_data[3]
            print(f"\n4. Signature (index 3):")
            print(f"   Type: {type(signature)}")
            if isinstance(signature, bytes):
                print(f"   Length: {len(signature)} bytes")
                print(f"   Hex: {signature.hex()}")
            
        else:
            print(f"Unexpected structure: {cwt_data}")
            
    except Exception as e:
        print(f"Error analyzing CWT: {e}")
        import traceback
        traceback.print_exc()

def main():
    if len(sys.argv) > 1:
        hex_data = sys.argv[1]
    else:
        # Use the provided hex data
        hex_data = "d83dd28443a10126a104582837383834323746423231383242333637364636384236313039364438303146344137384134313944585fa5016c7777772e6d6f7369702e696f041a6a53926e051a68725eee061a68725eee18a9583aa3041a499602d20769746573742d6461746118a9a504684a616e6520446f65086831393930303031303109020c6b30393837363534333231300d5847304502205d0a650f179e3298792c77bb7add5643a618aed2a2f1ec6ec44cf26a401f5b9c022100804b9355ccc7ab25bb881254b33bdebbce410f6740c6e93e90cf704502125a88"
    
    analyze_cwt_structure(hex_data)

if __name__ == "__main__":
    main() 