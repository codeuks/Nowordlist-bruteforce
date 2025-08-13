#!/usr/bin/env python3
"""
HashCrack - A powerful hash cracking tool similar to hashcat
Supports multiple hash algorithms, wordlists, and brute force attacks
"""

import hashlib
import argparse
import sys
import time
import threading
from pathlib import Path
from typing import List, Optional, Callable
import itertools
import string

class HashCrack:
    def __init__(self):
        self.hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
            'sha3_256': hashlib.sha3_256,
            'sha3_512': hashlib.sha3_512
        }
        
        self.charsets = {
            'lower': string.ascii_lowercase,
            'upper': string.ascii_uppercase,
            'digits': string.digits,
            'special': '`~!@#$%^&*()-_=+[{]}\\|;:\'"\',<.>/? ',
            'alphanumeric': string.ascii_letters + string.digits,
            'all': string.ascii_letters + string.digits + '`~!@#$%^&*()-_=+[{]}\\|;:\'"\',<.>/? '
        }
        
        self.found_password = None
        self.start_time = None
        self.attempts = 0
        self.stop_attack = False

    def get_hash(self, text: str, algorithm: str = 'md5') -> str:
        """Generate hash for given text using specified algorithm"""
        if algorithm not in self.hash_functions:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        hash_func = self.hash_functions[algorithm]
        return hash_func(text.encode('utf-8')).hexdigest()

    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load words from wordlist file"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Wordlist file '{wordlist_path}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            sys.exit(1)

    def dictionary_attack(self, target_hash: str, wordlist_path: str, algorithm: str = 'md5') -> Optional[str]:
        """Perform dictionary attack using wordlist"""
        print(f"[*] Starting dictionary attack with {algorithm.upper()}")
        print(f"[*] Target hash: {target_hash}")
        print(f"[*] Loading wordlist: {wordlist_path}")
        
        words = self.load_wordlist(wordlist_path)
        print(f"[*] Loaded {len(words)} words from wordlist")
        
        self.start_time = time.time()
        self.attempts = 0
        
        for word in words:
            if self.stop_attack:
                break
                
            self.attempts += 1
            word_hash = self.get_hash(word, algorithm)
            
            if word_hash == target_hash:
                elapsed = time.time() - self.start_time
                print(f"\n[+] Password found: '{word}'")
                print(f"[+] Hash: {word_hash}")
                print(f"[+] Attempts: {self.attempts:,}")
                print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                print(f"[+] Speed: {self.attempts/elapsed:.0f} hashes/second")
                return word
                
            if self.attempts % 10000 == 0:
                elapsed = time.time() - self.start_time
                speed = self.attempts / elapsed if elapsed > 0 else 0
                print(f"\r[*] Progress: {self.attempts:,}/{len(words):,} ({self.attempts/len(words)*100:.1f}%) - {speed:.0f} h/s", end='', flush=True)
        
        print(f"\n[-] Password not found in wordlist")
        print(f"[*] Total attempts: {self.attempts:,}")
        return None

    def brute_force_attack(self, target_hash: str, charset: str, min_length: int = 1, max_length: int = 8, algorithm: str = 'md5') -> Optional[str]:
        """Perform brute force attack"""
        print(f"[*] Starting brute force attack with {algorithm.upper()}")
        print(f"[*] Target hash: {target_hash}")
        print(f"[*] Charset: {charset}")
        print(f"[*] Length range: {min_length}-{max_length}")
        
        self.start_time = time.time()
        self.attempts = 0
        
        for length in range(min_length, max_length + 1):
            if self.stop_attack:
                break
                
            print(f"[*] Trying length {length}...")
            total_combinations = len(charset) ** length
            
            for combination in itertools.product(charset, repeat=length):
                if self.stop_attack:
                    break
                    
                self.attempts += 1
                candidate = ''.join(combination)
                candidate_hash = self.get_hash(candidate, algorithm)
                
                if candidate_hash == target_hash:
                    elapsed = time.time() - self.start_time
                    print(f"\n[+] Password found: '{candidate}'")
                    print(f"[+] Hash: {candidate_hash}")
                    print(f"[+] Attempts: {self.attempts:,}")
                    print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                    print(f"[+] Speed: {self.attempts/elapsed:.0f} hashes/second")
                    return candidate
                
                if self.attempts % 100000 == 0:
                    elapsed = time.time() - self.start_time
                    speed = self.attempts / elapsed if elapsed > 0 else 0
                    progress = self.attempts / total_combinations * 100 if total_combinations > 0 else 0
                    print(f"\r[*] Length {length}: {self.attempts:,}/{total_combinations:,} ({progress:.2f}%) - {speed:.0f} h/s", end='', flush=True)
        
        print(f"\n[-] Password not found")
        print(f"[*] Total attempts: {self.attempts:,}")
        return None

    def mask_attack(self, target_hash: str, mask: str, algorithm: str = 'md5') -> Optional[str]:
        """Perform mask attack (similar to hashcat masks)"""
        print(f"[*] Starting mask attack with {algorithm.upper()}")
        print(f"[*] Target hash: {target_hash}")
        print(f"[*] Mask: {mask}")
        
        # Define mask characters
        mask_chars = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': '`~!@#$%^&*()-_=+[{]}\\|;:\'"\',<.>/? ',
            '?a': string.ascii_letters + string.digits + '`~!@#$%^&*()-_=+[{]}\\|;:\'"\',<.>/? ',
            '?b': bytes(range(32, 127)).decode('ascii')
        }
        
        # Convert mask to charset list
        charsets = []
        i = 0
        while i < len(mask):
            if mask[i] == '?' and i + 1 < len(mask):
                char_type = mask[i:i+2]
                if char_type in mask_chars:
                    charsets.append(mask_chars[char_type])
                    i += 2
                else:
                    charsets.append([mask[i]])
                    i += 1
            else:
                charsets.append([mask[i]])
                i += 1
        
        self.start_time = time.time()
        self.attempts = 0
        total_combinations = 1
        for charset in charsets:
            total_combinations *= len(charset)
        
        print(f"[*] Total combinations: {total_combinations:,}")
        
        for combination in itertools.product(*charsets):
            if self.stop_attack:
                break
                
            self.attempts += 1
            candidate = ''.join(combination)
            candidate_hash = self.get_hash(candidate, algorithm)
            
            if candidate_hash == target_hash:
                elapsed = time.time() - self.start_time
                print(f"\n[+] Password found: '{candidate}'")
                print(f"[+] Hash: {candidate_hash}")
                print(f"[+] Attempts: {self.attempts:,}")
                print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                print(f"[+] Speed: {self.attempts/elapsed:.0f} hashes/second")
                return candidate
            
            if self.attempts % 100000 == 0:
                elapsed = time.time() - self.start_time
                speed = self.attempts / elapsed if elapsed > 0 else 0
                progress = self.attempts / total_combinations * 100 if total_combinations > 0 else 0
                print(f"\r[*] Progress: {self.attempts:,}/{total_combinations:,} ({progress:.2f}%) - {speed:.0f} h/s", end='', flush=True)
        
        print(f"\n[-] Password not found")
        print(f"[*] Total attempts: {self.attempts:,}")
        return None

    def stop(self):
        """Stop the current attack"""
        self.stop_attack = True
        print("\n[*] Attack stopped by user")

def main():
    parser = argparse.ArgumentParser(
        description="HashCrack - A powerful hash cracking tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dictionary attack
  python hashcrack.py -H 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt
  
  # Brute force attack
  python hashcrack.py -H 5d41402abc4b2a76b9719d911017c592 -b --charset all --min-length 1 --max-length 6
  
  # Mask attack
  python hashcrack.py -H 5d41402abc4b2a76b9719d911017c592 -m "?l?l?l?d?d"
  
  # Different hash algorithm
  python hashcrack.py -H a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 -w wordlist.txt --algorithm sha1
        """
    )
    
    parser.add_argument('-H', '--hash', required=True, help='Target hash to crack')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for dictionary attack')
    parser.add_argument('-b', '--brute-force', action='store_true', help='Use brute force attack')
    parser.add_argument('-m', '--mask', help='Mask for mask attack (e.g., "?l?l?l?d?d")')
    parser.add_argument('--algorithm', default='md5', choices=['md5', 'sha1', 'sha256', 'sha512', 'sha224', 'sha384', 'blake2b', 'blake2s', 'sha3_256', 'sha3_512'], help='Hash algorithm (default: md5)')
    parser.add_argument('--charset', default='all', choices=['lower', 'upper', 'digits', 'special', 'alphanumeric', 'all'], help='Character set for brute force (default: all)')
    parser.add_argument('--min-length', type=int, default=1, help='Minimum password length for brute force (default: 1)')
    parser.add_argument('--max-length', type=int, default=8, help='Maximum password length for brute force (default: 8)')
    parser.add_argument('--custom-charset', help='Custom character set for brute force')
    
    args = parser.parse_args()
    
    cracker = HashCrack()
    
    # Handle Ctrl+C gracefully
    def signal_handler(signum, frame):
        cracker.stop()
        sys.exit(0)
    
    try:
        import signal
        signal.signal(signal.SIGINT, signal_handler)
    except ImportError:
        pass
    
    print("=" * 60)
    print("HashCrack - Advanced Hash Cracking Tool")
    print("=" * 60)
    
    # Validate hash format
    if len(args.hash) not in [32, 40, 56, 64, 96, 128]:  # Common hash lengths
        print(f"[!] Warning: Hash length ({len(args.hash)}) doesn't match common hash lengths")
    
    # Determine attack type and execute
    if args.wordlist:
        if not Path(args.wordlist).exists():
            print(f"Error: Wordlist file '{args.wordlist}' not found.")
            sys.exit(1)
        result = cracker.dictionary_attack(args.hash, args.wordlist, args.algorithm)
    
    elif args.brute_force:
        charset = args.custom_charset if args.custom_charset else cracker.charsets[args.charset]
        result = cracker.brute_force_attack(args.hash, charset, args.min_length, args.max_length, args.algorithm)
    
    elif args.mask:
        result = cracker.mask_attack(args.hash, args.mask, args.algorithm)
    
    else:
        print("Error: Must specify either wordlist (-w), brute force (-b), or mask (-m)")
        parser.print_help()
        sys.exit(1)
    
    if result:
        print(f"\n[+] SUCCESS: Password is '{result}'")
        sys.exit(0)
    else:
        print(f"\n[-] FAILED: Password not found")
        sys.exit(1)

if __name__ == "__main__":
    main()