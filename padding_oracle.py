#!/usr/bin/env python3
"""
KPMG Padding Oracle Attack Implementation
Exploits PKCS#7 padding validation to decrypt AES-CBC ciphertext
"""

import requests
import base64
import binascii
from typing import List, Optional

class KMPGPaddingOracleAttacker:
    def __init__(self, base_url: str):
        """
        Initialize the KPMG padding oracle attacker
        
        Args:
            base_url: Base URL of the KPMG challenge server
        """
        self.base_url = base_url.rstrip('/')
        self.get_url = f"{self.base_url}/get_ciphertext"
        self.oracle_url = f"{self.base_url}/check_oracle"
        self.block_size = 16  # AES block size
        
        # Get the encrypted flag from the server
        self.iv_plus_ciphertext = self.get_encrypted_flag()
        self.blocks = self.split_into_blocks(self.iv_plus_ciphertext)
        
        print(f"Retrieved encrypted flag: {len(self.iv_plus_ciphertext)} bytes")
        print(f"Split into {len(self.blocks)} blocks of {self.block_size} bytes each")
    
    def get_encrypted_flag(self) -> bytes:
        """Get the encrypted flag from the server"""
        print(f"Fetching encrypted flag from {self.get_url}")
        
        try:
            response = requests.get(self.get_url, timeout=10)
            response.raise_for_status()
            
            # The server returns base64 encoded IV + ciphertext
            b64_data = response.text.strip()
            print(f"Received base64 data: {b64_data}")
            
            # Decode from base64 to get raw bytes
            return base64.b64decode(b64_data)
            
        except Exception as e:
            raise Exception(f"Failed to get encrypted flag: {e}")
        
    def split_into_blocks(self, data: bytes) -> List[bytes]:
        """Split data into 16-byte blocks"""
        return [data[i:i+self.block_size] for i in range(0, len(data), self.block_size)]
    
    def query_oracle(self, ciphertext: bytes) -> bool:
        """
        Query the KPMG padding oracle to check if decryption has valid padding
        
        Args:
            ciphertext: The ciphertext to test (IV + encrypted data)
            
        Returns:
            True if padding is valid, False otherwise
        """
        try:
            # Convert to base64 for transmission as required by KPMG API
            b64_data = base64.b64encode(ciphertext).decode('utf-8')
            
            # Make POST request to oracle with JSON body
            response = requests.post(self.oracle_url, 
                                   json={'ciphertext': b64_data}, 
                                   headers={'Content-Type': 'application/json'},
                                   timeout=10)
            
            # Check response - valid padding typically returns 200, invalid returns error
            if response.status_code == 200:
                return True
            else:
                return False
                
        except Exception as e:
            print(f"Oracle query failed: {e}")
            return False
    
    def attack_block(self, target_block: bytes, previous_block: bytes) -> bytes:
        """
        Attack a single block using padding oracle
        
        Args:
            target_block: The block to decrypt
            previous_block: The previous block (used as IV for this block)
            
        Returns:
            Decrypted plaintext block
        """
        print(f"Attacking block: {binascii.hexlify(target_block).decode()}")
        
        # Initialize arrays
        decrypted = [0] * self.block_size
        intermediate = [0] * self.block_size
        
        # Attack each byte from right to left
        for byte_pos in range(self.block_size - 1, -1, -1):
            padding_value = self.block_size - byte_pos
            print(f"  Attacking byte position {byte_pos}, padding value {padding_value}")
            
            # Create attack block
            attack_block = bytearray(previous_block)
            
            # Set up known bytes for current padding
            for known_pos in range(byte_pos + 1, self.block_size):
                attack_block[known_pos] = intermediate[known_pos] ^ padding_value
            
            # Try all possible values for current byte
            found = False
            for guess in range(256):
                attack_block[byte_pos] = guess
                
                # Create test ciphertext: attack_block + target_block
                test_ciphertext = bytes(attack_block) + target_block
                
                if self.query_oracle(test_ciphertext):
                    # Valid padding found!
                    intermediate[byte_pos] = guess ^ padding_value
                    decrypted[byte_pos] = intermediate[byte_pos] ^ previous_block[byte_pos]
                    
                    print(f"    Found byte {byte_pos}: 0x{decrypted[byte_pos]:02x} ('{chr(decrypted[byte_pos]) if 32 <= decrypted[byte_pos] <= 126 else '.'}')")
                    found = True
                    break
            
            if not found:
                print(f"    Failed to find byte at position {byte_pos}")
                # You might want to handle this case differently
                decrypted[byte_pos] = 0
        
        return bytes(decrypted)
    
    def decrypt_all_blocks(self) -> bytes:
        """
        Decrypt all blocks using padding oracle attack
        
        Returns:
            Complete decrypted plaintext
        """
        if len(self.blocks) < 2:
            raise ValueError("Need at least IV + 1 ciphertext block")
        
        plaintext_blocks = []
        
        # Attack each block (skip the IV/first block)
        for i in range(1, len(self.blocks)):
            print(f"\n=== Attacking Block {i} ===")
            previous_block = self.blocks[i-1]  # Previous block acts as IV
            current_block = self.blocks[i]
            
            decrypted_block = self.attack_block(current_block, previous_block)
            plaintext_blocks.append(decrypted_block)
        
        # Combine all plaintext blocks
        plaintext = b''.join(plaintext_blocks)
        
        # Remove PKCS#7 padding
        if plaintext:
            padding_length = plaintext[-1]
            if padding_length <= self.block_size:
                plaintext = plaintext[:-padding_length]
        
        return plaintext

def main():
    """
    Main function for KPMG Padding Oracle Challenge
    """
    print("KPMG Padding Oracle Attack Tool")
    print("=" * 50)
    
    # Get the base URL from user
    base_url = input("Enter the challenge base URL (e.g., http://challenge-server.com): ").strip()
    
    if not base_url:
        base_url = "http://localhost:8080"  # Default for testing
        print(f"Using default URL: {base_url}")
    
    try:
        # Create attacker instance and get encrypted flag
        attacker = KMPGPaddingOracleAttacker(base_url)
        
        print(f"\nOriginal ciphertext split into {len(attacker.blocks)} blocks:")
        for i, block in enumerate(attacker.blocks):
            print(f"Block {i}: {binascii.hexlify(block).decode()}")
        
        # Test the oracle with the original ciphertext first
        print(f"\nTesting oracle with original ciphertext...")
        original_valid = attacker.query_oracle(attacker.iv_plus_ciphertext)
        print(f"Original ciphertext has valid padding: {original_valid}")
        
        # Perform the attack
        print("\nStarting padding oracle attack...")
        plaintext = attacker.decrypt_all_blocks()
        
        print(f"\n{'='*50}")
        print("ATTACK SUCCESSFUL!")
        print(f"Decrypted plaintext (hex): {binascii.hexlify(plaintext).decode()}")
        print(f"Decrypted plaintext (ascii): {plaintext.decode('utf-8', errors='ignore')}")
        
        # Look for flag format
        flag_text = plaintext.decode('utf-8', errors='ignore')
        if 'flag{' in flag_text.lower() or 'kpmg{' in flag_text.lower():
            print(f"🚩 FLAG FOUND: {flag_text}")
        else:
            print(f"Flag candidate: {flag_text}")
        
    except Exception as e:
        print(f"Attack failed: {e}")
        print("\nTroubleshooting tips:")
        print("1. Verify the base URL is correct and accessible")
        print("2. Check that /get_ciphertext and /check_oracle endpoints are working")
        print("3. Ensure the server is running and responsive")
        print("4. Try testing the oracle manually first")

# Test function to verify oracle behavior
def test_oracle_manually(base_url: str):
    """
    Manual test function to verify oracle behavior
    """
    print("Testing KPMG Oracle Manually")
    print("=" * 30)
    
    try:
        # Test getting ciphertext
        get_url = f"{base_url.rstrip('/')}/get_ciphertext"
        print(f"1. Testing GET {get_url}")
        
        response = requests.get(get_url, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:100]}...")
        
        if response.status_code == 200:
            b64_data = response.text.strip()
            iv_plus_ciphertext = base64.b64decode(b64_data)
            
            # Test oracle with original (should be valid)
            oracle_url = f"{base_url.rstrip('/')}/check_oracle"
            print(f"\n2. Testing POST {oracle_url} with original ciphertext")
            
            oracle_response = requests.post(oracle_url, 
                                          json={'ciphertext': b64_data},
                                          headers={'Content-Type': 'application/json'},
                                          timeout=10)
            print(f"   Status: {oracle_response.status_code}")
            print(f"   Response: {oracle_response.text}")
            
            # Test oracle with corrupted data (should be invalid)
            print(f"\n3. Testing POST {oracle_url} with corrupted ciphertext")
            corrupted_data = base64.b64encode(b'A' * len(iv_plus_ciphertext)).decode()
            
            bad_response = requests.post(oracle_url, 
                                       json={'ciphertext': corrupted_data},
                                       headers={'Content-Type': 'application/json'},
                                       timeout=10)
            print(f"   Status: {bad_response.status_code}")
            print(f"   Response: {bad_response.text}")
            
            print(f"\n Oracle test complete!")
            print(f"Original data valid: {oracle_response.status_code == 200}")
            print(f"Corrupted data invalid: {bad_response.status_code != 200}")
            
    except Exception as e:
        print(f" Manual test failed: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # Manual testing mode
        base_url = input("Enter base URL for manual testing: ").strip()
        test_oracle_manually(base_url)
    else:
        # Normal attack mode
        main()