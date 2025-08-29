# CyberSource Python SOAP Toolkit

Python implementation of the CyberSource SOAP Toolkit compatible with Debian Stretch and Python 3.5+.

## Prerequisites

- Python 3.5 or higher
- Debian Stretch compatible system libraries
- P12 certificate from CyberSource

## Installation

### On Debian Stretch:

```bash
# Run the setup script
chmod +x setup.sh
./setup.sh

# Or manually install dependencies
sudo apt-get update
sudo apt-get install python3-dev python3-pip python3-lxml python3-openssl
pip3 install -r requirements.txt
```

### Using Docker:

```bash
# Build and run with Docker
docker-compose up --build

# Or build manually
docker build -t cybersource-python .
docker run -v /path/to/certificates:/app/certificates cybersource-python
```

## Configuration

Set these environment variables:

```bash
export CYBERSOURCE_KEY_ALIAS="your_key_alias"
export CYBERSOURCE_KEY_FILE="certificate.p12"
export CYBERSOURCE_KEY_PASS="your_password"
export CYBERSOURCE_KEY_DIRECTORY="/path/to/certificates"
```

## Usage

```python
from cybersource import CyberSourceClient

# Client automatically loads configuration from environment variables
client = CyberSourceClient(
    "https://ics2wstest.ic3.com/commerce/1.x/transactionProcessor/CyberSourceTransaction_1.219.wsdl"
)

# Build and send transaction
request = {
    'merchantID': 'your_merchant_id',
    'merchantReferenceCode': 'your_ref_code',
    'ccAuthService': {'run': 'true'},
    # ... other request fields
}

response = client.run_transaction(request)
print(f"Decision: {response.get('decision')}")
```

## Running the Sample

```bash
# Update MERCHANT_ID in sample.py first
python3 sample.py
```

## File Structure

```
PythonSoapToolkit/
├── cybersource/          # Main Python package
│   ├── __init__.py      # Package initialization
│   ├── client.py        # SOAP client implementation
│   ├── security.py      # Security and signing utilities
│   └── config.py        # Configuration handling
├── sample.py            # Usage example
├── requirements.txt     # Dependencies
├── setup.sh            # Setup script
├── Dockerfile          # Docker configuration
└── README.md           # This file
```