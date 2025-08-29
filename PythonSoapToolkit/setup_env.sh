#!/bin/bash
# Environment setup for CyberSource SOAP Toolkit

export CYBERSOURCE_KEY_ALIAS="your_actual_key_alias"
export CYBERSOURCE_KEY_FILE="your_certificate.p12"
export CYBERSOURCE_KEY_PASS="your_actual_password"
export CYBERSOURCE_KEY_DIRECTORY="/path/to/your/certificates"

echo "Environment variables set for CyberSource SOAP Toolkit"
echo "KEY_ALIAS: $CYBERSOURCE_KEY_ALIAS"
echo "KEY_FILE: $CYBERSOURCE_KEY_FILE"
echo "KEY_DIRECTORY: $CYBERSOURCE_KEY_DIRECTORY"