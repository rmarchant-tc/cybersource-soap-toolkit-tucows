#!/usr/bin/env python3
"""
CyberSource SOAP Toolkit Sample
Demonstrates how to use the Python SOAP client
"""

import os
import sys
import base64
from cybersource import CyberSourceClient

def short_uid(nbytes=9):
    # 9 bytes → 12 URL-safe chars (A–Z, a–z, 0–9, _ and -)
    return base64.urlsafe_b64encode(os.urandom(nbytes)).rstrip(b'=').decode('ascii')


def main():
    """Run a sample CyberSource transaction"""
    
    # Configuration
    MERCHANT_ID = 'tuctest'
    WSDL_URL = 'https://ics2wstest.ic3.com/commerce/1.x/transactionProcessor/CyberSourceTransaction_1.219.wsdl'
    
    # Ensure environment variables are set
    required_env_vars = [
        'CYBERSOURCE_KEY_ALIAS',
        'CYBERSOURCE_KEY_FILE', 
        'CYBERSOURCE_KEY_PASS',
        'CYBERSOURCE_KEY_DIRECTORY'
    ]
    
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    if missing_vars:
        print("Error: Missing environment variables: {0}".format(', '.join(missing_vars)))
        print("\nPlease set the following environment variables:")
        print("export CYBERSOURCE_KEY_ALIAS='YOUR KEY ALIAS'")
        print("export CYBERSOURCE_KEY_FILE='YOUR CERTIFICATE FILE'")
        print("export CYBERSOURCE_KEY_PASS='YOUR KEY PASS'")
        print("export CYBERSOURCE_KEY_DIRECTORY='PATH TO CERTIFICATES'")
        sys.exit(1)
    
    try:
        # Create SOAP client
        client = CyberSourceClient(WSDL_URL)
        
        # Build transaction request
        request = {
            'merchantID': MERCHANT_ID,
            'merchantReferenceCode': 'py_tx_98765_' + short_uid(),
            
            # Client information for troubleshooting
            'clientLibrary': 'Python',
            'clientLibraryVersion': '{0}.{1}.{2}'.format(*sys.version_info[:3]),
            'clientEnvironment': os.uname().sysname if hasattr(os, 'uname') else 'Unknown',
            
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
            
            # Credit card information
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
        
        # Run the transaction
        print("Sending transaction request...")
        reply = client.run_transaction(request)
        
        # Display results
        print("DECISION                    : {0}".format(reply.get('decision', 'N/A')))
        print("REASON CODE                 : {0}".format(reply.get('reasonCode', 'N/A')))
        print("REQUEST ID                  : {0}".format(reply.get('requestID', 'N/A')))
        print("REQUEST TOKEN               : {0}".format(reply.get('requestToken', 'N/A')))
        
        # CC Auth Reply information
        cc_auth_reply = reply.get('ccAuthReply', {})
        if cc_auth_reply:
            print("CCAUTHREPLY -> REASON CODE  : {0}".format(cc_auth_reply.get('reasonCode', 'N/A')))
        
    except Exception as e:
        print("Error: {0}".format(str(e)))
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
