#!/usr/bin/env python3
"""
Password Hash Generator

This script generates password hashes in PHC format with the following specifications:
- PBKDF2: sha256/sha512 with 600k-1M/210k-1M iterations respectively
- bcrypt: cost factor 10-14
- scrypt: N=16384, r=8, p=1 (or custom parameters)
- Argon2: Argon2id with memory 64MB-1GB, time 1-10, parallelism 1-4
"""

import hashlib
import hmac
import base64
import secrets
import argparse
import re
from typing import Tuple, Optional
from enum import Enum

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    import scrypt
    SCRYPT_AVAILABLE = True
except ImportError:
    SCRYPT_AVAILABLE = False

try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    PBKDF2 = "pbkdf2"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"
    ARGON2 = "argon2"


def generate_salt(length: int = 16) -> bytes:
    """Generate a random salt of specified length."""
    return secrets.token_bytes(length)


def pbkdf2(password: str, salt: bytes, iterations: int, digest: str) -> bytes:
    """
    Generate PBKDF2 hash using the specified parameters.
    
    Args:
        password: The password to hash
        salt: The salt bytes
        iterations: Number of iterations
        digest: Hash algorithm ('sha256' or 'sha512')
    
    Returns:
        The PBKDF2 hash as bytes
    """
    if digest == 'sha256':
        hash_func = hashlib.sha256
    elif digest == 'sha512':
        hash_func = hashlib.sha512
    else:
        raise ValueError(f"Unsupported digest algorithm: {digest}")
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # PBKDF2 implementation
    key = b''
    block = 1
    
    while len(key) < hash_func().digest_size:
        # U1 = HMAC(password, salt || block_number)
        u = hmac.new(password, salt + block.to_bytes(4, 'big'), hash_func).digest()
        result = u
        
        # U2 = HMAC(password, U1)
        # U3 = HMAC(password, U2)
        # ... and so on for iterations
        for _ in range(1, iterations):
            u = hmac.new(password, u, hash_func).digest()
            result = bytes(a ^ b for a, b in zip(result, u))
        
        key += result
        block += 1
    
    return key[:hash_func().digest_size]


def bcrypt_hash(password: str, salt: bytes, cost: int) -> bytes:
    """
    Generate bcrypt hash using the specified parameters.
    
    Args:
        password: The password to hash
        salt: The salt bytes (must be 16 bytes for bcrypt)
        cost: The cost factor (log2 of iterations)
    
    Returns:
        The bcrypt hash as bytes
    """
    if not BCRYPT_AVAILABLE:
        raise ImportError("bcrypt library not available. Install with: pip install bcrypt")
    
    if len(salt) != 16:
        raise ValueError("bcrypt requires exactly 16 bytes of salt")
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Generate bcrypt hash
    hash_bytes = bcrypt.hashpw(password, salt, cost)
    
    # Extract the hash part (remove the salt prefix)
    # bcrypt format: $2b$cost$salt$hash
    parts = hash_bytes.decode('ascii').split('$')
    if len(parts) != 4:
        raise ValueError("Invalid bcrypt hash format")
    
    # Return just the hash part
    return base64.b64decode(parts[3] + "==")  # Add padding


def scrypt_hash(password: str, salt: bytes, N: int, r: int, p: int) -> bytes:
    """
    Generate scrypt hash using the specified parameters.
    
    Args:
        password: The password to hash
        salt: The salt bytes
        N: CPU/memory cost parameter (must be power of 2)
        r: Block size parameter
        p: Parallelization parameter
    
    Returns:
        The scrypt hash as bytes
    """
    if not SCRYPT_AVAILABLE:
        raise ImportError("scrypt library not available. Install with: pip install scrypt")
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Generate scrypt hash
    hash_bytes = scrypt.hash(password, salt, N=N, r=r, p=p)
    
    return hash_bytes


def argon2_hash(password: str, salt: bytes, memory_cost: int, time_cost: int, parallelism: int) -> bytes:
    """
    Generate Argon2id hash using the specified parameters.
    
    Args:
        password: The password to hash
        salt: The salt bytes
        memory_cost: Memory cost in KB
        time_cost: Time cost (iterations)
        parallelism: Parallelism factor
    
    Returns:
        The Argon2 hash as bytes
    """
    if not ARGON2_AVAILABLE:
        raise ImportError("argon2 library not available. Install with: pip install argon2-cffi")
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Generate Argon2id hash
    hash_bytes = argon2.hash_password(
        password,
        salt,
        type=argon2.Type.ID,
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism
    )
    
    return hash_bytes


def validate_pbkdf2_parameters(digest: str, iterations: int) -> None:
    """Validate PBKDF2 parameters."""
    if digest not in ['sha256', 'sha512']:
        raise ValueError(f"Unsupported digest algorithm: {digest}. Must be 'sha256' or 'sha512'")
    
    if digest == 'sha256':
        if not 600000 <= iterations <= 1000000:
            raise ValueError(f"sha256 requires 600,000 to 1,000,000 iterations, got {iterations}")
    elif digest == 'sha512':
        if not 210000 <= iterations <= 1000000:
            raise ValueError(f"sha512 requires 210,000 to 1,000,000 iterations, got {iterations}")


def validate_bcrypt_parameters(cost: int) -> None:
    """Validate bcrypt parameters."""
    if not 10 <= cost <= 14:
        raise ValueError(f"bcrypt cost must be between 10 and 14, got {cost}")


def validate_scrypt_parameters(N: int, r: int, p: int) -> None:
    """Validate scrypt parameters."""
    if not (N & (N - 1) == 0) or N < 16384:
        raise ValueError(f"scrypt N must be a power of 2 and at least 16384, got {N}")
    
    if not 1 <= r <= 8:
        raise ValueError(f"scrypt r must be between 1 and 8, got {r}")
    
    if not 1 <= p <= 4:
        raise ValueError(f"scrypt p must be between 1 and 4, got {p}")


def validate_argon2_parameters(memory_cost: int, time_cost: int, parallelism: int) -> None:
    """Validate Argon2 parameters."""
    if not 65536 <= memory_cost <= 1048576:  # 64MB to 1GB
        raise ValueError(f"Argon2 memory_cost must be between 65536 and 1048576 KB, got {memory_cost}")
    
    if not 1 <= time_cost <= 10:
        raise ValueError(f"Argon2 time_cost must be between 1 and 10, got {time_cost}")
    
    if not 1 <= parallelism <= 4:
        raise ValueError(f"Argon2 parallelism must be between 1 and 4, got {parallelism}")


def generate_hash(password: str, algorithm: HashAlgorithm, **kwargs) -> str:
    """
    Generate a password hash in PHC format.
    
    Args:
        password: The password to hash
        algorithm: The hash algorithm to use
        **kwargs: Algorithm-specific parameters
    
    Returns:
        PHC formatted hash string
    """
    if algorithm == HashAlgorithm.PBKDF2:
        digest = kwargs.get('digest', 'sha256')
        iterations = kwargs.get('iterations')
        if iterations is None:
            iterations = 600000 if digest == 'sha256' else 210000
        
        validate_pbkdf2_parameters(digest, iterations)
        salt = generate_salt(16)
        hash_bytes = pbkdf2(password, salt, iterations, digest)
        
        salt_b64 = base64.b64encode(salt).decode('ascii').rstrip('=')
        hash_b64 = base64.b64encode(hash_bytes).decode('ascii').rstrip('=')
        
        # Escape dollar signs in salt and hash
        salt_b64 = salt_b64.replace('$', '\\$')
        hash_b64 = hash_b64.replace('$', '\\$')
        
        # WorkOS expects format: \$pbkdf2\$i=600000,d=sha256\$salt\$hash
        return f"\\$pbkdf2\\$i={iterations},d={digest}\\${salt_b64}\\${hash_b64}"
    
    elif algorithm == HashAlgorithm.BCRYPT:
        cost = kwargs.get('cost', 12)
        validate_bcrypt_parameters(cost)
        salt = generate_salt(16)
        hash_bytes = bcrypt_hash(password, salt, cost)
        
        salt_b64 = base64.b64encode(salt).decode('ascii').rstrip('=')
        hash_b64 = base64.b64encode(hash_bytes).decode('ascii').rstrip('=')
        
        # Escape dollar signs in salt and hash
        salt_b64 = salt_b64.replace('$', '\\$')
        hash_b64 = hash_b64.replace('$', '\\$')
        
        return f"$bcrypt$c={cost}${salt_b64}${hash_b64}"
    
    elif algorithm == HashAlgorithm.SCRYPT:
        N = kwargs.get('N', 16384)
        r = kwargs.get('r', 8)
        p = kwargs.get('p', 1)
        validate_scrypt_parameters(N, r, p)
        salt = generate_salt(16)
        hash_bytes = scrypt_hash(password, salt, N, r, p)
        
        salt_b64 = base64.b64encode(salt).decode('ascii').rstrip('=')
        hash_b64 = base64.b64encode(hash_bytes).decode('ascii').rstrip('=')
        
        # Escape dollar signs in salt and hash
        salt_b64 = salt_b64.replace('$', '\\$')
        hash_b64 = hash_b64.replace('$', '\\$')
        
        return f"$scrypt$N={N},r={r},p={p}${salt_b64}${hash_b64}"
    
    elif algorithm == HashAlgorithm.ARGON2:
        memory_cost = kwargs.get('memory_cost', 65536)  # 64MB
        time_cost = kwargs.get('time_cost', 3)
        parallelism = kwargs.get('parallelism', 1)
        validate_argon2_parameters(memory_cost, time_cost, parallelism)
        salt = generate_salt(16)
        hash_bytes = argon2_hash(password, salt, memory_cost, time_cost, parallelism)
        
        salt_b64 = base64.b64encode(salt).decode('ascii').rstrip('=')
        hash_b64 = base64.b64encode(hash_bytes).decode('ascii').rstrip('=')
        
        # Escape dollar signs in salt and hash
        salt_b64 = salt_b64.replace('$', '\\$')
        hash_b64 = hash_b64.replace('$', '\\$')
        
        return f"$argon2id$m={memory_cost},t={time_cost},p={parallelism}${salt_b64}${hash_b64}"
    
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def main():
    """Main function to handle command line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate password hashes in PHC format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # PBKDF2 with SHA256 (default)
  python password_generator.py "mypassword"
  
  # PBKDF2 with SHA512
  python password_generator.py "mypassword" --algorithm pbkdf2 --digest sha512
  
  # bcrypt with cost 12
  python password_generator.py "mypassword" --algorithm bcrypt --cost 12
  
  # scrypt with custom parameters
  python password_generator.py "mypassword" --algorithm scrypt --N 32768 --r 8 --p 1
  
  # Argon2id with custom parameters
  python password_generator.py "mypassword" --algorithm argon2 --memory-cost 131072 --time-cost 4 --parallelism 2
        """
    )
    
    parser.add_argument('password', help='Password to hash')
    parser.add_argument('--algorithm', choices=['pbkdf2', 'bcrypt', 'scrypt', 'argon2'], 
                       default='pbkdf2', help='Hash algorithm (default: pbkdf2)')
    
    # PBKDF2 options
    parser.add_argument('--digest', choices=['sha256', 'sha512'], default='sha256',
                       help='Digest algorithm for PBKDF2 (default: sha256)')
    parser.add_argument('--iterations', type=int,
                       help='Number of iterations for PBKDF2 (uses minimum if not specified)')
    
    # bcrypt options
    parser.add_argument('--cost', type=int, default=12,
                       help='Cost factor for bcrypt (default: 12)')
    
    # scrypt options
    parser.add_argument('--N', type=int, default=16384,
                       help='CPU/memory cost parameter for scrypt (default: 16384)')
    parser.add_argument('--r', type=int, default=8,
                       help='Block size parameter for scrypt (default: 8)')
    parser.add_argument('--p', type=int, default=1,
                       help='Parallelization parameter for scrypt (default: 1)')
    
    # Argon2 options
    parser.add_argument('--memory-cost', type=int, default=65536,
                       help='Memory cost in KB for Argon2 (default: 65536)')
    parser.add_argument('--time-cost', type=int, default=3,
                       help='Time cost for Argon2 (default: 3)')
    parser.add_argument('--parallelism', type=int, default=1,
                       help='Parallelism factor for Argon2 (default: 1)')
    
    args = parser.parse_args()
    
    try:
        algorithm = HashAlgorithm(args.algorithm)
        
        # Prepare kwargs based on algorithm
        kwargs = {}
        if algorithm == HashAlgorithm.PBKDF2:
            kwargs['digest'] = args.digest
            if args.iterations:
                kwargs['iterations'] = args.iterations
        elif algorithm == HashAlgorithm.BCRYPT:
            kwargs['cost'] = args.cost
        elif algorithm == HashAlgorithm.SCRYPT:
            kwargs['N'] = args.N
            kwargs['r'] = args.r
            kwargs['p'] = args.p
        elif algorithm == HashAlgorithm.ARGON2:
            kwargs['memory_cost'] = args.memory_cost
            kwargs['time_cost'] = args.time_cost
            kwargs['parallelism'] = args.parallelism
        
        hash_result = generate_hash(args.password, algorithm, **kwargs)
        print(f"{algorithm.value.upper()} Hash: {hash_result}")
        
    except (ValueError, ImportError) as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main()) 