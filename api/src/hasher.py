
import hashlib
import hmac
import struct

def get_api_hash(value: str, key: int):
    """
    Generate an HMAC-MD5 hash of the supplied string using an Int64 as the key. 
    This is useful for unique hash based API lookups.
    
    Args:
        value (str): String to hash.
        key (int): 64-bit integer to initialize the keyed hash object 
                  (e.g. 0xabc or 0x1122334455667788).
    
    Returns:
        str: The computed MD5 hash value as uppercase hex string.
    """
    # Convert string to lowercase and encode as UTF-8
    data = value.lower().encode('utf-8')
    
    # Convert 64-bit integer to bytes (little-endian, matching C# BitConverter)
    key_bytes = struct.pack('<q', key)
    
    # Create HMAC-MD5 hash
    hash_obj = hmac.new(key_bytes, data, hashlib.md5)
    
    # Get the hash bytes and convert to uppercase hex string without separators
    return hash_obj.hexdigest().upper()