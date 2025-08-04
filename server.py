#!/usr/bin/env python3
"""
Simple HTTP server for the Password Hash Generator web interface.
"""

import http.server
import socketserver
import os
import sys
from pathlib import Path

def main():
    # Get the directory where this script is located
    script_dir = Path(__file__).parent.absolute()
    
    # Change to the script directory
    os.chdir(script_dir)
    
    # Set up the server
    PORT = 8000
    
    # Check if port is available, try next port if not
    for port in range(8000, 8010):
        try:
            with socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
                print(f"🚀 Password Hash Generator web interface")
                print(f"📱 Open your browser and go to: http://localhost:{port}")
                print(f"📁 Serving files from: {script_dir}")
                print(f"⏹️  Press Ctrl+C to stop the server")
                print()
                
                # Start the server
                httpd.serve_forever()
                break
        except OSError:
            if port == 8009:  # Last port in range
                print("❌ Error: No available ports found in range 8000-8009")
                sys.exit(1)
            continue
        except KeyboardInterrupt:
            print("\n👋 Server stopped. Goodbye!")
            break

if __name__ == "__main__":
    main() 