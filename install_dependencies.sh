#!/bin/bash

# Password Hash Generator - Dependency Installer
# This script installs optional dependencies for additional hash algorithms

echo "Installing optional dependencies for Password Hash Generator..."

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 not found. Please install Python and pip first."
    exit 1
fi

# Install bcrypt for bcrypt algorithm support
echo "Installing bcrypt..."
pip3 install bcrypt>=4.0.0

# Install scrypt for scrypt algorithm support
echo "Installing scrypt..."
pip3 install scrypt>=0.8.20

# Install argon2-cffi for Argon2 algorithm support
echo "Installing argon2-cffi..."
pip3 install argon2-cffi>=21.3.0

echo ""
echo "Installation complete!"
echo ""
echo "You can now use all hash algorithms:"
echo "  - PBKDF2 (built-in, no dependencies required)"
echo "  - bcrypt (requires bcrypt library)"
echo "  - scrypt (requires scrypt library)"
echo "  - Argon2 (requires argon2-cffi library)"
echo ""
echo "Example usage:"
echo "  python3 password_generator.py 'mypassword' --algorithm bcrypt"
echo "  python3 password_generator.py 'mypassword' --algorithm scrypt"
echo "  python3 password_generator.py 'mypassword' --algorithm argon2" 