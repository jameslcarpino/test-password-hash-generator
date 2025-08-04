# Password Hash Generator

This script generates password hashes in PHC (Password Hashing Competition) format with support for multiple algorithms commonly used in migration scenarios.

## Features

- **PBKDF2**: SHA256/SHA512 with configurable iterations (600k-1M/210k-1M respectively)
- **bcrypt**: Cost factor 10-14 with secure defaults
- **scrypt**: Configurable N, r, p parameters with secure defaults
- **Argon2**: Argon2id with memory, time, and parallelism controls
- Configurable parameters within security limits for each algorithm
- Generates cryptographically secure random salts
- Outputs in standard PHC format
- Command-line interface with argument parsing
- **Web interface** with minimalistic UI
- Graceful handling of missing optional dependencies

## Requirements

- Python 3.6 or higher
- **Core functionality**: No external dependencies (uses only standard library modules)
- **Optional algorithms**: Install additional packages for bcrypt, scrypt, and Argon2

### Installing Optional Dependencies

```bash
# Install all optional dependencies
pip install -r requirements.txt

# Or install individually
pip install bcrypt>=4.0.0
pip install scrypt>=0.8.20
pip install argon2-cffi>=21.3.0
```

## Usage

### Web Interface (Recommended for UI)

```bash
# Start the web server
python3 server.py

# Then open your browser to http://localhost:8000
```

The web interface provides a clean, minimalistic UI for generating password hashes with all supported algorithms.

### Command Line Interface

#### Basic Usage (PBKDF2 - Default)

```bash
python password_generator.py "your_password"
```

This will generate a PBKDF2 hash using SHA256 with 600,000 iterations (the minimum for SHA256).

#### PBKDF2 Examples

```bash
# PBKDF2 with SHA256 (default)
python password_generator.py "mypassword"

# PBKDF2 with SHA512
python password_generator.py "mypassword" --algorithm pbkdf2 --digest sha512

# PBKDF2 with custom iterations
python password_generator.py "mypassword" --algorithm pbkdf2 --digest sha256 --iterations 800000
```

#### bcrypt Examples

```bash
# bcrypt with default cost (12)
python password_generator.py "mypassword" --algorithm bcrypt

# bcrypt with custom cost
python password_generator.py "mypassword" --algorithm bcrypt --cost 14
```

#### scrypt Examples

```bash
# scrypt with default parameters (N=16384, r=8, p=1)
python password_generator.py "mypassword" --algorithm scrypt

# scrypt with custom parameters
python password_generator.py "mypassword" --algorithm scrypt --N 32768 --r 8 --p 1
```

#### Argon2 Examples

```bash
# Argon2id with default parameters
python password_generator.py "mypassword" --algorithm argon2

# Argon2id with custom parameters
python password_generator.py "mypassword" --algorithm argon2 --memory-cost 131072 --time-cost 4 --parallelism 2
```

### Command Line Options

- `password`: The password to hash (required)
- `--algorithm`: Hash algorithm (`pbkdf2`, `bcrypt`, `scrypt`, `argon2`, default: `pbkdf2`)

#### PBKDF2 Options
- `--digest`: Digest algorithm (`sha256` or `sha512`, default: `sha256`)
- `--iterations`: Number of iterations (uses minimum if not specified)

#### bcrypt Options
- `--cost`: Cost factor (10-14, default: 12)

#### scrypt Options
- `--N`: CPU/memory cost parameter (power of 2, min 16384, default: 16384)
- `--r`: Block size parameter (1-8, default: 8)
- `--p`: Parallelization parameter (1-4, default: 1)

#### Argon2 Options
- `--memory-cost`: Memory cost in KB (65536-1048576, default: 65536)
- `--time-cost`: Time cost (1-10, default: 3)
- `--parallelism`: Parallelism factor (1-4, default: 1)

## Security Parameters

### PBKDF2
- **SHA256**: 600,000 to 1,000,000 iterations
- **SHA512**: 210,000 to 1,000,000 iterations
- **Default**: SHA256 with 600,000 iterations

### bcrypt
- **Cost factor**: 10 to 14 (log2 of iterations)
- **Default**: Cost 12 (4096 iterations)

### scrypt
- **N**: Power of 2, minimum 16384
- **r**: 1 to 8
- **p**: 1 to 4
- **Default**: N=16384, r=8, p=1

### Argon2
- **Memory cost**: 64MB to 1GB (65536-1048576 KB)
- **Time cost**: 1 to 10 iterations
- **Parallelism**: 1 to 4 threads
- **Default**: 64MB memory, 3 iterations, 1 thread

## Output Format

The script generates hashes in PHC format for each algorithm:

### PBKDF2
```
$pbkdf2$i=600000,d=sha256$T2ptRFh6MXhDQVh2SWZuUGdpQXBUTg$xXiyTisD7390NijyCv5ICMhFW4eDuMlzypRoLGLyIvA
```

### bcrypt
```
$bcrypt$c=12$T2ptRFh6MXhDQVh2SWZuUGdpQXBUTg$xXiyTisD7390NijyCv5ICMhFW4eDuMlzypRoLGLyIvA
```

### scrypt
```
$scrypt$N=16384,r=8,p=1$T2ptRFh6MXhDQVh2SWZuUGdpQXBUTg$xXiyTisD7390NijyCv5ICMhFW4eDuMlzypRoLGLyIvA
```

### Argon2
```
$argon2id$m=65536,t=3,p=1$T2ptRFh6MXhDQVh2SWZuUGdpQXBUTg$xXiyTisD7390NijyCv5ICMhFW4eDuMlzypRoLGLyIvA
```

## Examples

```bash
# Generate PBKDF2 hash with default settings
$ python password_generator.py "mypassword"
PBKDF2 Hash: $pbkdf2$i=600000,d=sha256$T2ptRFh6MXhDQVh2SWZuUGdpQXBUTg$xXiyTisD7390NijyCv5ICMhFW4eDuMlzypRoLGLyIvA

# Generate bcrypt hash
$ python password_generator.py "mypassword" --algorithm bcrypt
BCRYPT Hash: $bcrypt$c=12$T2ptRFh6MXhDQVh2SWZuUGdpQXBUTg$xXiyTisD7390NijyCv5ICMhFW4eDuMlzypRoLGLyIvA

# Generate scrypt hash with custom parameters
$ python password_generator.py "mypassword" --algorithm scrypt --N 32768
SCRYPT Hash: $scrypt$N=32768,r=8,p=1$T2ptRFh6MXhDQVh2SWZuUGdpQXBUTg$xXiyTisD7390NijyCv5ICMhFW4eDuMlzypRoLGLyIvA

# Generate Argon2 hash with custom parameters
$ python password_generator.py "mypassword" --algorithm argon2 --memory-cost 131072 --time-cost 4
ARGON2 Hash: $argon2id$m=131072,t=4,p=1$T2ptRFh6MXhDQVh2SWZuUGdpQXBUTg$xXiyTisD7390NijyCv5ICMhFW4eDuMlzypRoLGLyIvA
```

## Migration Use Cases

This script is particularly useful for password migration scenarios:

### From Legacy Systems
- **MD5/SHA1**: Migrate to PBKDF2 with high iteration counts
- **Old bcrypt**: Upgrade to higher cost factors or Argon2
- **Simple hashes**: Convert to any of the supported algorithms

### To WorkOS User Management
- Generate compatible hashes for user migration
- Support multiple algorithms during transition period
- Maintain security standards during migration

### Cross-Platform Compatibility
- Generate hashes compatible with various systems
- Support different security requirements
- Provide consistent PHC format output

## Error Handling

The script includes comprehensive error handling:

- Validates algorithm parameters within security ranges
- Provides clear error messages for invalid parameters
- Gracefully handles missing optional dependencies
- Validates input parameters for each algorithm

## Security Notes

- The script uses `secrets.token_bytes()` for cryptographically secure salt generation
- All parameter limits are enforced to ensure security compliance
- Each algorithm follows industry best practices and standards
- Salt length is fixed at 16 bytes for consistency across algorithms
- Optional dependencies are handled gracefully with informative error messages

## Dependencies

### Required
- Python 3.6+ (standard library only for PBKDF2)

### Optional
- `bcrypt>=4.0.0` - For bcrypt algorithm support
- `scrypt>=0.8.20` - For scrypt algorithm support  
- `argon2-cffi>=21.3.0` - For Argon2 algorithm support

## License

This script is provided as-is for educational and development purposes. 