#!/usr/bin/env python3
"""
CyberSource SOAP Client with P12 Certificate Authentication
Compatible with Python 3.5+ and Debian Stretch
"""

import os
import sys
import xml.etree.ElementTree as ET
import http.client
import ssl
import urllib.parse
from .security import SecurityUtils
from .config import PropertiesUtils


class CyberSourceClient:
    """
    Extended SOAP Client with P12 Certificate Token Authentication
    Equivalent to PHP ExtendedClientWithToken class
    """
    
    # WS-Security namespaces
    WSU_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
    WSSE_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/'
    DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
    
    def __init__(self, wsdl_url, ssl_options=None):
        """
        Initialize client with WSDL URL and SSL options from environment
        
        Args:
            wsdl_url (str): CyberSource WSDL URL
            ssl_options (dict): SSL configuration (optional, uses env vars if None)
        """
        self.wsdl_url = wsdl_url
        self.properties_util = PropertiesUtils()
        self.security_util = SecurityUtils()
        
        # Load SSL options from environment variables if not provided
        if ssl_options is None:
            ssl_options = {
                'KEY_ALIAS': os.environ.get('CYBERSOURCE_KEY_ALIAS'),
                'KEY_FILE': os.environ.get('CYBERSOURCE_KEY_FILE'),
                'KEY_PASS': os.environ.get('CYBERSOURCE_KEY_PASS'),
                'KEY_DIRECTORY': os.environ.get('CYBERSOURCE_KEY_DIRECTORY')
            }
        
        self.ssl_options = ssl_options
        self._validate_ssl_options()
        
        # Parse WSDL URL for HTTP requests
        parsed_url = urllib.parse.urlparse(wsdl_url)
        self.host = parsed_url.netloc
        self.path = parsed_url.path
        self.port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        self.use_ssl = parsed_url.scheme == 'https'
        
    def _validate_ssl_options(self):
        """Validate SSL options using PropertiesUtils"""
        if not self.properties_util.is_valid_file_path(self.ssl_options):
            raise ValueError("Invalid SSL certificate configuration")
            
    def run_transaction(self, request_data):
        """
        Run a CyberSource transaction
        
        Args:
            request_data (dict): Transaction request data
            
        Returns:
            dict: Transaction response
        """
        # Build SOAP request
        soap_request = self._build_soap_request(request_data)
        
        # Add security headers with P12 authentication
        signed_request = self._add_security_headers(soap_request)
        
        # Send HTTP request
        response_xml = self._send_http_request(signed_request)
        
        # Parse and return response
        return self._parse_response(response_xml)
    
    def _build_soap_request(self, request_data):
        """
        Build SOAP envelope from request data
        
        Args:
            request_data (dict): Request data
            
        Returns:
            str: SOAP XML string
        """
        # Create SOAP envelope
        envelope = ET.Element('{{{0}}}Envelope'.format(self.SOAP_NS))
        envelope.set('xmlns:soap', self.SOAP_NS)
        
        # Create SOAP header (will be populated by security)
        header = ET.SubElement(envelope, '{{{0}}}Header'.format(self.SOAP_NS))
        
        # Create SOAP body
        body = ET.SubElement(envelope, '{{{0}}}Body'.format(self.SOAP_NS))
        
        # Add transaction request
        run_transaction = ET.SubElement(body, 'runTransaction')
        request_elem = ET.SubElement(run_transaction, 'request')
        
        # Convert request data to XML elements
        self._dict_to_xml(request_data, request_elem)
        
        return ET.tostring(envelope, encoding='unicode')
    
    def _dict_to_xml(self, data, parent):
        """
        Convert dictionary to XML elements (Python 3.5 compatible)
        
        Args:
            data (dict): Data to convert
            parent (Element): Parent XML element
        """
        for key, value in data.items():
            if isinstance(value, dict):
                child = ET.SubElement(parent, key)
                self._dict_to_xml(value, child)
            elif isinstance(value, list):
                for item in value:
                    child = ET.SubElement(parent, key)
                    if isinstance(item, dict):
                        self._dict_to_xml(item, child)
                    else:
                        child.text = str(item)
            else:
                child = ET.SubElement(parent, key)
                child.text = str(value)
    
    def _add_security_headers(self, soap_request):
        """
        Add WS-Security headers with P12 certificate authentication
        
        Args:
            soap_request (str): Original SOAP request
            
        Returns:
            str: SOAP request with security headers
        """
        # Parse the SOAP request
        root = ET.fromstring(soap_request)
        
        # Register namespaces for XPath
        namespaces = {
            'soap': self.SOAP_NS,
            'wsu': self.WSU_NS,
            'wsse': self.WSSE_NS,
            'ds': self.DS_NS
        }
        
        # Find SOAP body and add wsu:Id attribute
        body = root.find('.//soap:Body', namespaces)
        if body is not None:
            body.set('{{{0}}}Id'.format(self.WSU_NS), 'Body')
        
        # Find or create SOAP header
        header = root.find('.//soap:Header', namespaces)
        if header is None:
            # Insert header before body
            body_index = list(root).index(body)
            header = ET.Element('{{{0}}}Header'.format(self.SOAP_NS))
            root.insert(body_index, header)
        
        # Create Security element
        security = ET.SubElement(header, '{{{0}}}Security'.format(self.WSSE_NS))
        security.set('xmlns:wsse', self.WSSE_NS)
        security.set('xmlns:wsu', self.WSU_NS)
        
        # Generate and add Binary Security Token
        cert_path = self.properties_util.get_file_path(self.ssl_options)
        cert_password = self.properties_util.get_certificate_password(self.ssl_options)
        
        token_element, private_key = self.security_util.generate_security_token(
            root, cert_path, cert_password
        )
        security.append(token_element)
        
        # Create and add digital signature
        signature_element = self.security_util.create_signature(
            root, private_key, ['Body']
        )
        security.append(signature_element)
        
        return ET.tostring(root, encoding='unicode')
    
    def _send_http_request(self, soap_request):
        """
        Send HTTP request to CyberSource
        
        Args:
            soap_request (str): SOAP request XML
            
        Returns:
            str: Response XML
        """
        # Prepare headers
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': 'runTransaction',
            'Content-Length': str(len(soap_request.encode('utf-8')))
        }
        
        # Create HTTP connection
        if self.use_ssl:
            # Create SSL context for HTTPS
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(self.host, self.port, context=context)
        else:
            conn = http.client.HTTPConnection(self.host, self.port)
        
        try:
            # Send request
            conn.request('POST', self.path, soap_request.encode('utf-8'), headers)
            
            # Get response
            response = conn.getresponse()
            response_data = response.read().decode('utf-8')
            
            if response.status != 200:
                raise Exception('HTTP Error {0}: {1}'.format(response.status, response.reason))
            
            return response_data
            
        finally:
            conn.close()
    
    def _parse_response(self, response_xml):
        """
        Parse SOAP response XML into dictionary
        
        Args:
            response_xml (str): Response XML
            
        Returns:
            dict: Parsed response data
        """
        try:
            root = ET.fromstring(response_xml)
            
            # Find the response body
            namespaces = {'soap': self.SOAP_NS}
            body = root.find('.//soap:Body', namespaces)
            
            if body is None:
                raise Exception('Invalid SOAP response: no Body element found')
            
            # Find runTransactionResponse
            response_elem = None
            for child in body:
                if 'runTransactionResponse' in child.tag:
                    response_elem = child
                    break
            
            if response_elem is None:
                raise Exception('Invalid response: no runTransactionResponse found')
            
            # Find the reply element
            reply_elem = None
            for child in response_elem:
                if 'reply' in child.tag:
                    reply_elem = child
                    break
            
            if reply_elem is None:
                raise Exception('Invalid response: no reply element found')
            
            # Convert XML to dictionary
            return self._xml_to_dict(reply_elem)
            
        except ET.ParseError as e:
            raise Exception('Failed to parse response XML: {0}'.format(str(e)))
    
    def _xml_to_dict(self, element):
        """
        Convert XML element to dictionary (Python 3.5 compatible)
        
        Args:
            element (Element): XML element to convert
            
        Returns:
            dict: Converted data
        """
        result = {}
        
        # Handle element text
        if element.text and element.text.strip():
            if len(element) == 0:  # Leaf element
                return element.text.strip()
            else:
                result['_text'] = element.text.strip()
        
        # Handle child elements
        for child in element:
            tag_name = child.tag.split('}')[-1]  # Remove namespace
            child_data = self._xml_to_dict(child)
            
            if tag_name in result:
                # Handle multiple elements with same tag
                if not isinstance(result[tag_name], list):
                    result[tag_name] = [result[tag_name]]
                result[tag_name].append(child_data)
            else:
                result[tag_name] = child_data
        
        return result
