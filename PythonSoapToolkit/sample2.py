#!/usr/bin/env python3
"""
CyberSource SOAP Toolkit Sample with comprehensive debugging
Shows all request/response details including HTTP headers and body
Compatible with Python 3.5+
"""

import os
import sys
import logging
import base64
import xml.etree.ElementTree as ET
from cybersource import CyberSourceClient

def short_uid(nbytes=9):
    # 9 bytes → 12 URL-safe chars (A–Z, a–z, 0–9, _ and -)
    return base64.urlsafe_b64encode(os.urandom(nbytes)).rstrip(b'=').decode('ascii')

# Configure comprehensive logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('cybersource_debug.log')
    ]
)

logger = logging.getLogger(__name__)

def pretty_print_xml(xml_string, label="XML"):
    """Pretty print XML for debugging - Python 3.5 compatible"""
    try:
        root = ET.fromstring(xml_string)
        # Simple pretty printing (Python 3.5 compatible)
        def indent(elem, level=0):
            i = "\n" + level * "  "
            if len(elem):
                if not elem.text or not elem.text.strip():
                    elem.text = i + "  "
                if not elem.tail or not elem.tail.strip():
                    elem.tail = i
                for elem in elem:
                    indent(elem, level + 1)
                if not elem.tail or not elem.tail.strip():
                    elem.tail = i
            else:
                if level and (not elem.tail or not elem.tail.strip()):
                    elem.tail = i
        
        indent(root)
        pretty_xml = ET.tostring(root, encoding='unicode')
        print("\n=== {} ===".format(label))  # Python 3.5 compatible
        print(pretty_xml)
        print("=== End {} ===\n".format(label))  # Python 3.5 compatible
        return pretty_xml
    except Exception as e:
        print("\n=== {} (Raw - parsing failed: {}) ===".format(label, e))  # Python 3.5 compatible
        print(xml_string)
        print("=== End {} ===\n".format(label))  # Python 3.5 compatible
        return xml_string

def main():
    """Main function to test CyberSource SOAP client with full debugging"""
    
    print("=== CyberSource Python SOAP Toolkit Debug Sample ===")
    print("This will show ALL request and response details for debugging")
    print("")
    
    # Check environment variables
    required_env_vars = [
        'CYBERSOURCE_KEY_ALIAS',
        'CYBERSOURCE_KEY_FILE', 
        'CYBERSOURCE_KEY_PASS',
        'CYBERSOURCE_KEY_DIRECTORY'
    ]
    
    print("=== Environment Variables ===")
    missing_vars = []
    for var in required_env_vars:
        value = os.getenv(var)
        if value:
            if 'PASS' in var:
                print("{}: {}".format(var, '*' * len(value)))  # Hide password
            else:
                print("{}: {}".format(var, value))
        else:
            missing_vars.append(var)
            print("{}: NOT SET".format(var))
    
    if missing_vars:
        print("\nERROR: Missing required environment variables: {}".format(missing_vars))
        print("Please set these variables before running the sample.")
        return 1
    
    # Check certificate file
    cert_dir = os.getenv('CYBERSOURCE_KEY_DIRECTORY')
    cert_file = os.getenv('CYBERSOURCE_KEY_FILE')
    cert_path = os.path.join(cert_dir, cert_file)
    
    print("\n=== Certificate File Check ===")
    print("Certificate path: {}".format(cert_path))
    if os.path.exists(cert_path):
        file_size = os.path.getsize(cert_path)
        print("Certificate file exists, size: {} bytes".format(file_size))
    else:
        print("ERROR: Certificate file not found!")
        return 1
    
    try:
        # Update this to your actual merchant ID
        MERCHANT_ID = 'tuctest'  # Change this to your merchant ID
        
        print("\n=== Creating SOAP Client ===")
        print("Merchant ID: {}".format(MERCHANT_ID))
        
        # WSDL URL (using same as PHP sample)
        wsdl_url = "https://ics2wstest.ic3.com/commerce/1.x/transactionProcessor/CyberSourceTransaction_1.219.wsdl"
        print("WSDL URL: {}".format(wsdl_url))
        
        # Create client with debug mode
        client = CyberSourceClient(wsdl_url, debug=True)
        
        print("\n=== Building Transaction Request ===")
        
        # Generate unique reference code - Python 3.5 compatible
        import random
        import time
        ref_code = 'TR_PYTHON_{}_{}'.format(os.getpid(), int(time.time() * 1000) % 1000000)
        
        # Build request (same structure as PHP sample)
        request = {
            'merchantID': MERCHANT_ID,
            'merchantReferenceCode': ref_code,
            
            # Client library info
            'clientLibrary': 'Python',
            'clientLibraryVersion': sys.version,
            'clientEnvironment': '{}/{}'.format(sys.platform, os.name),
            
            # Credit card authorization service
            'ccAuthService': {
                'run': 'true'
            },
            
            # Billing information
            'billTo': {
                'firstName': 'John',
                'lastName': 'Doe', 
                'street1': '1295 Charleston Road',
                'city': 'Mountain View',
                'state': 'CA',
                'postalCode': '94043',
                'country': 'US',
                'email': 'null@cybersource.com',
                'ipAddress': '10.7.111.111'
            },
            
            # Credit card info
            'card': {
                'accountNumber': '4111111111111111',
                'expirationMonth': '12',
                'expirationYear': '2035'
            },
            
            # Purchase totals
            'purchaseTotals': {
                'currency': 'USD'
            },
            
            # Items
            'item': [
                {
                    'id': '0',
                    'unitPrice': '12.34',
                    'quantity': '2'
                },
                {
                    'id': '1', 
                    'unitPrice': '56.78'
                }
            ]
        }
        
        print("Request structure:")
        for key, value in request.items():
            if isinstance(value, dict):
                print("  {}: {} with {} fields".format(key, type(value).__name__, len(value)))
            elif isinstance(value, list):
                print("  {}: {} with {} items".format(key, type(value).__name__, len(value)))
            else:
                print("  {}: {}".format(key, value))
        
        print("\n=== Sending Transaction ===")
        print("This will show the full SOAP request and response...")
        
        # Send the transaction
        response = client.run_transaction(request)
        
        print("\n=== Transaction Results ===")
        
        if response:
            print("SUCCESS: Received response from CyberSource")
            
            # Show key response fields
            decision = response.get('decision', 'N/A')
            reason_code = response.get('reasonCode', 'N/A') 
            request_id = response.get('requestID', 'N/A')
            request_token = response.get('requestToken', 'N/A')
            
            print("Decision: {}".format(decision))
            print("Reason Code: {}".format(reason_code))
            print("Request ID: {}".format(request_id))
            print("Request Token: {}".format(request_token))
            
            # CC Auth specific results
            cc_auth_reply = response.get('ccAuthReply', {})
            if cc_auth_reply:
                cc_reason = cc_auth_reply.get('reasonCode', 'N/A')
                print("CC Auth Reason Code: {}".format(cc_reason))
            
            # Show full response structure
            print("\nFull response structure:")
            def print_response_structure(obj, indent=0):
                prefix = "  " * indent
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if isinstance(value, (dict, list)):
                            print("{}{}:{}".format(prefix, key, type(value).__name__))
                            print_response_structure(value, indent + 1)
                        else:
                            print("{}{}: {}".format(prefix, key, value))
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        print("{}[{}]: {}".format(prefix, i, type(item).__name__))
                        print_response_structure(item, indent + 1)
            
            print_response_structure(response)
            
        else:
            print("ERROR: No response received")
            return 1
            
    except Exception as e:
        print("\n=== ERROR OCCURRED ===")
        print("Error type: {}".format(type(e).__name__))
        print("Error message: {}".format(str(e)))
        
        # Print full exception details
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()
        
        # If it's an HTTP error, try to get more details
        if hasattr(e, 'response'):
            print("\nHTTP Response Details:")
            print("Status: {}".format(getattr(e.response, 'status', 'N/A')))
            print("Reason: {}".format(getattr(e.response, 'reason', 'N/A')))
            if hasattr(e.response, 'read'):
                try:
                    body = e.response.read()
                    if isinstance(body, bytes):
                        body = body.decode('utf-8', errors='replace')
                    pretty_print_xml(body, "Error Response Body")
                except:
                    print("Response body: {}".format(body))
        
        return 1
    
    print("\n=== Sample Complete ===")
    return 0

if __name__ == '__main__':
    sys.exit(main())
