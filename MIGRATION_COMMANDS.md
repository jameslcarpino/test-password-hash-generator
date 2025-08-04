# Password Migration Commands

Quick reference for common password migration scenarios using the Password Hash Generator.

## Installation

```bash
# Install optional dependencies for all algorithms
./install_dependencies.sh

# Or install manually
pip3 install bcrypt>=4.0.0 scrypt>=0.8.20 argon2-cffi>=21.3.0
```

## Migration Scenarios

### From Legacy MD5/SHA1 to PBKDF2
```bash
# High-security migration to PBKDF2-SHA256
python3 password_generator.py "user_password" --algorithm pbkdf2 --digest sha256 --iterations 1000000

# High-security migration to PBKDF2-SHA512
python3 password_generator.py "user_password" --algorithm pbkdf2 --digest sha512 --iterations 1000000
```

### From Old bcrypt to Modern bcrypt
```bash
# Upgrade to higher cost factor
python3 password_generator.py "user_password" --algorithm bcrypt --cost 14

# Standard modern bcrypt
python3 password_generator.py "user_password" --algorithm bcrypt --cost 12
```

### From Any Legacy to Argon2 (Recommended)
```bash
# High-security Argon2id
python3 password_generator.py "user_password" --algorithm argon2 --memory-cost 262144 --time-cost 5 --parallelism 2

# Standard Argon2id
python3 password_generator.py "user_password" --algorithm argon2 --memory-cost 131072 --time-cost 4 --parallelism 1
```

### From Legacy to scrypt
```bash
# High-security scrypt
python3 password_generator.py "user_password" --algorithm scrypt --N 32768 --r 8 --p 1

# Standard scrypt
python3 password_generator.py "user_password" --algorithm scrypt --N 16384 --r 8 --p 1
```

## WorkOS Migration Commands

### For User Management Migration
```bash
# Generate compatible hashes for WorkOS User Management
python3 password_generator.py "user_password" --algorithm pbkdf2 --digest sha256 --iterations 600000

# For high-security requirements
python3 password_generator.py "user_password" --algorithm argon2 --memory-cost 131072 --time-cost 3 --parallelism 1
```

### Batch Migration Script Example
```bash
#!/bin/bash
# migrate_passwords.sh

while IFS=',' read -r username password; do
    echo "Migrating password for user: $username"
    hash=$(python3 password_generator.py "$password" --algorithm argon2 --memory-cost 131072 --time-cost 3 --parallelism 1)
    echo "$username,$hash" >> migrated_users.csv
done < legacy_users.csv
```

## Security Recommendations

### For Critical Systems
- Use Argon2id with high memory cost (262144 KB = 256MB)
- Use PBKDF2-SHA512 with 1,000,000 iterations
- Use bcrypt with cost 14

### For Standard Systems
- Use Argon2id with standard parameters
- Use PBKDF2-SHA256 with 600,000+ iterations
- Use bcrypt with cost 12

### For Legacy Compatibility
- Use PBKDF2-SHA256 with minimum iterations
- Use bcrypt with cost 10-12

## Output Formats

All commands generate PHC-formatted hashes:

```
# PBKDF2
$pbkdf2$i=600000,d=sha256$salt$hash

# bcrypt
$bcrypt$c=12$salt$hash

# scrypt
$scrypt$N=16384,r=8,p=1$salt$hash

# Argon2
$argon2id$m=131072,t=3,p=1$salt$hash
```

## Error Handling

The script validates all parameters and provides clear error messages:

```bash
# Invalid iterations for SHA256
python3 password_generator.py "password" --algorithm pbkdf2 --iterations 500000
# Error: sha256 requires 600,000 to 1,000,000 iterations, got 500000

# Missing dependency
python3 password_generator.py "password" --algorithm bcrypt
# Error: bcrypt library not available. Install with: pip install bcrypt
```

## Performance Notes

- **PBKDF2**: Fastest, good for high iteration counts
- **bcrypt**: Good balance of security and performance
- **scrypt**: Memory-hard, good against GPU attacks
- **Argon2**: Most secure, but slower than others

Choose based on your security requirements and performance constraints. 