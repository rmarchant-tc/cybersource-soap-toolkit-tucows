#!/bin/bash
# Setup script for CyberSource Python SOAP Toolkit on Debian Stretch

echo "Setting up CyberSource Python SOAP Toolkit for Debian Stretch..."

# Check if running in Docker
if [ -f /.dockerenv ]; then
    echo "Running in Docker container - sources.list already fixed"
else
    echo "Running on host system"
    # Note: On host Debian Stretch, you may need to update sources.list manually
    echo "If apt-get fails, copy debian-stretch/sources.list to /etc/apt/sources.list"
fi

# Install system dependencies
echo "Installing system packages..."
apt-get update || echo "Note: apt-get update failed - may need sources.list fix"
apt-get install -y python3-dev python3-pip python3-venv || echo "Some packages may be missing"
apt-get install -y python3-lxml python3-openssl || echo "Python packages may need pip install"
apt-get install -y libssl-dev libffi-dev openssl || echo "Development libraries may be missing"

# Create virtual environment (optional but recommended)
echo "Creating virtual environment..."
python3 -m venv cybersource_env || echo "venv creation failed - may not be available"
if [ -d cybersource_env ]; then
    source cybersource_env/bin/activate
    echo "Virtual environment activated"
fi

# Install Python dependencies
echo "Installing Python packages..."
pip3 install --upgrade pip || echo "pip upgrade failed"
pip3 install -r requirements.txt || echo "Some pip packages may have failed"

echo "Setup complete!"
echo ""
echo "To use the toolkit:"
echo "1. Set environment variables:"
echo "   export CYBERSOURCE_KEY_ALIAS='your_key_alias'"
echo "   export CYBERSOURCE_KEY_FILE='certificate.p12'"
echo "   export CYBERSOURCE_KEY_PASS='your_password'"
echo "   export CYBERSOURCE_KEY_DIRECTORY='/path/to/certificates'"
echo ""
echo "2. Update MERCHANT_ID in sample.py"
echo ""
echo "3. Run the sample:"
echo "   python3 sample.py"
echo ""
echo "Or test with Docker:"
echo "   docker-compose up --build"