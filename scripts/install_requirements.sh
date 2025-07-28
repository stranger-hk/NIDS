#!/bin/bash

echo "🔧 Installing NIDS requirements..."

# Update system packages
sudo apt-get update

# Install Python dependencies
pip install -r requirements.txt

# Install system dependencies for packet capture
sudo apt-get install -y libpcap-dev tcpdump

# Set capabilities for packet capture (optional, for non-root execution)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

echo "✅ Requirements installed successfully!"
echo "📝 Note: You may need to run the application with sudo for packet capture"
echo "🚀 Run 'python scripts/setup_database.py' to initialize the database"
