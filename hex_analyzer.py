#!/usr/bin/env python3
"""
Simple Hex Analyzer for CBOR/CWT data
"""

def hex_to_bytes(hex_string):
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_string)

def decode_cbor_tag(data, offset=0):
    """Decode CBOR tag and return the tagged value"""
    if offset >= len(data):
        return None, offset
    
    byte = data[offset]
    major_type = (byte >> 5) & 0x07
    additional_info = byte & 0x1F
    
    if major_type != 6:  # Not a tag
        return None, offset
    
    offset += 1
    
    # Get tag value
    tag_value = 0
    if additional_info < 24:
        tag_value = additional_info
    elif additional_info == 24:
        if offset < len(data):
            tag_value = data[offset]
            offset += 1
        else:
            return None, offset
    elif additional_info == 25:
        if offset + 1 < len(data):
            tag_value = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
        else:
            return None, offset
    elif additional_info == 26:
        if offset + 3 < len(data):
            tag_value = int.from_bytes(data[offset:offset+4], 'big')
            offset += 4
        else:
            return None, offset
    elif additional_info == 27:
        if offset + 7 < len(data):
            tag_value = int.from_bytes(data[offset:offset+8], 'big')
            offset += 8
        else:
            return None, offset
    
    print(f"  CBOR Tag value: {tag_value}")
    
    # Now decode the tagged value
    if offset >= len(data):
        return None, offset
    
    tagged_byte = data[offset]
    tagged_major_type = (tagged_byte >> 5) & 0x07
    tagged_additional_info = tagged_byte & 0x1F
    
    print(f"  Tagged value - Major type: {tagged_major_type}, Additional info: {tagged_additional_info}")
    
    # For now, just return the remaining data as the tagged value
    return data[offset:], offset

def analyze_hex_structure(hex_data):
    """Analyze the hex structure to understand CBOR format"""
    print("=" * 80)
    print("HEX STRUCTURE ANALYSIS")
    print("=" * 80)
    
    try:
        # Convert hex to bytes
        print(f"Input hex length: {len(hex_data)} characters")
        cbor_bytes = hex_to_bytes(hex_data)
        print(f"Decoded bytes length: {len(cbor_bytes)} bytes")
        
        # Show first few bytes to understand structure
        print(f"\nFirst 32 bytes: {cbor_bytes[:32].hex()}")
        print(f"First 32 bytes as ASCII: {repr(cbor_bytes[:32])}")
        
        # Analyze the first byte to understand CBOR major type
        if len(cbor_bytes) > 0:
            first_byte = cbor_bytes[0]
            major_type = (first_byte >> 5) & 0x07
            additional_info = first_byte & 0x1F
            
            print(f"\nFirst byte analysis:")
            print(f"  First byte: 0x{first_byte:02x}")
            print(f"  Major type: {major_type}")
            print(f"  Additional info: {additional_info}")
            
            major_types = {
                0: "unsigned integer",
                1: "negative integer", 
                2: "byte string",
                3: "text string",
                4: "array",
                5: "map",
                6: "tag",
                7: "simple/float"
            }
            
            print(f"  Major type meaning: {major_types.get(major_type, 'unknown')}")
            
            # Handle CBOR tag
            if major_type == 6:
                print(f"\nThis is a CBOR tag")
                tagged_data, offset = decode_cbor_tag(cbor_bytes)
                if tagged_data is not None:
                    print(f"  Tagged data length: {len(tagged_data)} bytes")
                    print(f"  Tagged data (hex): {tagged_data.hex()[:50]}...")
                    
                    # Now analyze the tagged data
                    if len(tagged_data) > 0:
                        tagged_first_byte = tagged_data[0]
                        tagged_major_type = (tagged_first_byte >> 5) & 0x07
                        tagged_additional_info = tagged_first_byte & 0x1F
                        
                        print(f"\nTagged data analysis:")
                        print(f"  First byte: 0x{tagged_first_byte:02x}")
                        print(f"  Major type: {tagged_major_type} ({major_types.get(tagged_major_type, 'unknown')})")
                        print(f"  Additional info: {tagged_additional_info}")
                        
                        # If it's an array (major type 4), analyze COSESign1 structure
                        if tagged_major_type == 4:
                            print(f"\nThis appears to be a COSESign1 structure (tagged array)")
                            print("Expected structure: [protected_header, unprotected_header, payload, signature]")
                            
                            # Try to find the boundaries of each element
                            array_offset = 0
                            if tagged_additional_info == 24:  # 1-byte length
                                if len(tagged_data) > 1:
                                    array_length = tagged_data[1]
                                    array_offset = 2
                                    print(f"  Array length (1-byte): {array_length}")
                                else:
                                    print("  Insufficient data for array length")
                                    return
                            elif tagged_additional_info == 25:  # 2-byte length
                                if len(tagged_data) > 2:
                                    array_length = int.from_bytes(tagged_data[1:3], 'big')
                                    array_offset = 3
                                    print(f"  Array length (2-byte): {array_length}")
                                else:
                                    print("  Insufficient data for array length")
                                    return
                            else:
                                array_length = tagged_additional_info
                                print(f"  Array length (immediate): {array_length}")
                            
                            print(f"  Array starts at offset: {array_offset}")
                            
                            # Try to decode each element
                            current_offset = array_offset
                            for i in range(array_length):
                                if current_offset >= len(tagged_data):
                                    print(f"  Element {i}: Insufficient data")
                                    break
                                
                                element_byte = tagged_data[current_offset]
                                element_major_type = (element_byte >> 5) & 0x07
                                element_additional_info = element_byte & 0x1F
                                
                                print(f"\n  Element {i}:")
                                print(f"    First byte: 0x{element_byte:02x}")
                                print(f"    Major type: {element_major_type} ({major_types.get(element_major_type, 'unknown')})")
                                print(f"    Additional info: {element_additional_info}")
                                
                                # Try to determine element length
                                element_length = 0
                                length_bytes = 0
                                
                                if element_major_type in [2, 3, 4, 5]:  # byte string, text string, array, map
                                    if element_additional_info < 24:
                                        element_length = element_additional_info
                                        length_bytes = 0
                                    elif element_additional_info == 24:
                                        if current_offset + 1 < len(tagged_data):
                                            element_length = tagged_data[current_offset + 1]
                                            length_bytes = 1
                                        else:
                                            print(f"    Insufficient data for length")
                                            break
                                    elif element_additional_info == 25:
                                        if current_offset + 2 < len(tagged_data):
                                            element_length = int.from_bytes(tagged_data[current_offset + 1:current_offset + 3], 'big')
                                            length_bytes = 2
                                        else:
                                            print(f"    Insufficient data for length")
                                            break
                                    elif element_additional_info == 26:
                                        if current_offset + 4 < len(tagged_data):
                                            element_length = int.from_bytes(tagged_data[current_offset + 1:current_offset + 5], 'big')
                                            length_bytes = 4
                                        else:
                                            print(f"    Insufficient data for length")
                                            break
                                    
                                    print(f"    Element length: {element_length} bytes")
                                    print(f"    Length bytes: {length_bytes}")
                                    
                                    # Show the element data
                                    element_start = current_offset + 1 + length_bytes
                                    element_end = element_start + element_length
                                    
                                    if element_end <= len(tagged_data):
                                        element_data = tagged_data[element_start:element_end]
                                        print(f"    Element data (hex): {element_data.hex()[:50]}...")
                                        
                                        if element_major_type == 3:  # text string
                                            try:
                                                text_data = element_data.decode('utf-8')
                                                print(f"    Element data (text): {text_data}")
                                            except UnicodeDecodeError:
                                                print(f"    Element data (binary): {repr(element_data)}")
                                        
                                        current_offset = element_end
                                    else:
                                        print(f"    Element data: Insufficient bytes")
                                        break
                                else:
                                    # For other types, just advance by 1 byte for now
                                    current_offset += 1
                                    print(f"    Element data: Single byte value")
            
            elif major_type == 4:  # array
                print(f"\nThis appears to be a CBOR array with {additional_info} elements")
                print("Expected COSESign1 structure: [protected_header, unprotected_header, payload, signature]")
                
                # Try to find the boundaries of each element
                offset = 1
                if additional_info == 24:  # 1-byte length
                    if len(cbor_bytes) > 1:
                        array_length = cbor_bytes[1]
                        offset = 2
                        print(f"  Array length (1-byte): {array_length}")
                    else:
                        print("  Insufficient data for array length")
                        return
                elif additional_info == 25:  # 2-byte length
                    if len(cbor_bytes) > 2:
                        array_length = int.from_bytes(cbor_bytes[1:3], 'big')
                        offset = 3
                        print(f"  Array length (2-byte): {array_length}")
                    else:
                        print("  Insufficient data for array length")
                        return
                else:
                    array_length = additional_info
                    print(f"  Array length (immediate): {array_length}")
                
                print(f"  Array starts at offset: {offset}")
                
                # Try to decode each element
                for i in range(array_length):
                    if offset >= len(cbor_bytes):
                        print(f"  Element {i}: Insufficient data")
                        break
                    
                    element_byte = cbor_bytes[offset]
                    element_major_type = (element_byte >> 5) & 0x07
                    element_additional_info = element_byte & 0x1F
                    
                    print(f"\n  Element {i}:")
                    print(f"    First byte: 0x{element_byte:02x}")
                    print(f"    Major type: {element_major_type} ({major_types.get(element_major_type, 'unknown')})")
                    print(f"    Additional info: {element_additional_info}")
                    
                    # Try to determine element length
                    element_length = 0
                    length_bytes = 0
                    
                    if element_major_type in [2, 3, 4, 5]:  # byte string, text string, array, map
                        if element_additional_info < 24:
                            element_length = element_additional_info
                            length_bytes = 0
                        elif element_additional_info == 24:
                            if offset + 1 < len(cbor_bytes):
                                element_length = cbor_bytes[offset + 1]
                                length_bytes = 1
                            else:
                                print(f"    Insufficient data for length")
                                break
                        elif element_additional_info == 25:
                            if offset + 2 < len(cbor_bytes):
                                element_length = int.from_bytes(cbor_bytes[offset + 1:offset + 3], 'big')
                                length_bytes = 2
                            else:
                                print(f"    Insufficient data for length")
                                break
                        elif element_additional_info == 26:
                            if offset + 4 < len(cbor_bytes):
                                element_length = int.from_bytes(cbor_bytes[offset + 1:offset + 5], 'big')
                                length_bytes = 4
                            else:
                                print(f"    Insufficient data for length")
                                break
                        
                        print(f"    Element length: {element_length} bytes")
                        print(f"    Length bytes: {length_bytes}")
                        
                        # Show the element data
                        element_start = offset + 1 + length_bytes
                        element_end = element_start + element_length
                        
                        if element_end <= len(cbor_bytes):
                            element_data = cbor_bytes[element_start:element_end]
                            print(f"    Element data (hex): {element_data.hex()[:50]}...")
                            
                            if element_major_type == 3:  # text string
                                try:
                                    text_data = element_data.decode('utf-8')
                                    print(f"    Element data (text): {text_data}")
                                except UnicodeDecodeError:
                                    print(f"    Element data (binary): {repr(element_data)}")
                            
                            offset = element_end
                        else:
                            print(f"    Element data: Insufficient bytes")
                            break
                    else:
                        # For other types, just advance by 1 byte for now
                        offset += 1
                        print(f"    Element data: Single byte value")
            
            elif major_type == 2:  # byte string
                print(f"\nThis appears to be a CBOR byte string")
                if additional_info < 24:
                    length = additional_info
                    offset = 1
                elif additional_info == 24:
                    if len(cbor_bytes) > 1:
                        length = cbor_bytes[1]
                        offset = 2
                    else:
                        print("  Insufficient data for length")
                        return
                else:
                    print(f"  Unsupported length encoding: {additional_info}")
                    return
                
                print(f"  Byte string length: {length}")
                print(f"  Byte string starts at offset: {offset}")
                
                if offset + length <= len(cbor_bytes):
                    byte_string_data = cbor_bytes[offset:offset + length]
                    print(f"  Byte string data (hex): {byte_string_data.hex()}")
                    print(f"  Byte string data (repr): {repr(byte_string_data)}")
                else:
                    print(f"  Byte string data: Insufficient bytes")
        
    except Exception as e:
        print(f"Error analyzing hex: {e}")
        import traceback
        traceback.print_exc()

def main():
    # Use the provided hex data
    hex_data = "d83dd28443a10126a104582837383834323746423231383242333637364636384236313039364438303146344137384134313944585fa5016c7777772e6d6f7369702e696f041a6a53926e051a68725eee061a68725eee18a9583aa3041a499602d20769746573742d6461746118a9a504684a616e6520446f65086831393930303031303109020c6b30393837363534333231300d5847304502205d0a650f179e3298792c77bb7add5643a618aed2a2f1ec6ec44cf26a401f5b9c022100804b9355ccc7ab25bb881254b33bdebbce410f6740c6e93e90cf704502125a88"
    
    analyze_hex_structure(hex_data)

if __name__ == "__main__":
    main() 