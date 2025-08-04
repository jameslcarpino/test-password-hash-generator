#!/bin/bash

# Password Hash Generator - Web Interface Launcher
# This script starts the web interface for the password hash generator

echo "🚀 Starting Password Hash Generator Web Interface..."
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 not found. Please install Python 3 first."
    exit 1
fi

# Check if server.py exists
if [ ! -f "server.py" ]; then
    echo "❌ Error: server.py not found. Please run this script from the project directory."
    exit 1
fi

# Start the server
echo "📱 Starting web server..."
echo "🌐 The web interface will be available at: http://localhost:8000"
echo "⏹️  Press Ctrl+C to stop the server"
echo ""

python3 server.py 