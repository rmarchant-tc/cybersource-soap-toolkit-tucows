#!/usr/bin/env python3
"""
CyberSource SOAP Client with P12 Certificate Authentication
Compatible with Python 3.5+ and Debian Stretch

This version extends the original (baseline) implementation you provided by adding:
 - Explicit constants (SOAP action, namespaces) for clarity.
 - ssl_options enrichment (auto-detect certificate_type, KEY_ALIAS retention).
 - Timeout support (default 6000 ms like PHP ExtendedClientWithToken).
 - Detailed debug logging (optional) for:
     * Built SOAP (unsigned & signed) XML (pretty and raw)
     * HTTP request line, headers, and body length
     * HTTP response status, headers, and body (always captured; printed when debug)
     * Error responses (non-200) with body dump
 - Storage of last request/response metadata for post-mortem inspection.
 - Optional pretty-printing that preserves Python 3.5 compatibility.
 - Safe redaction of sensitive fields in debug output.
 - Endpoint path auto-adjustment if a WSDL URL is supplied (strip trailing *.wsdl).
The core flow, method names, and structure of the original file are preserved to keep diffs small.
"""

import os
import sys
import xml.etree.ElementTree as ET
import http.client
import ssl
import urllib.parse
import socket
import time

from .security import SecurityUtils
from .config import PropertiesUtils

# -----------------------------------------------------------------------------
# Constants (kept explicit for easy reference & diff readability)
# -----------------------------------------------------------------------------
WSU_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
WSSE_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/'
DS_NS = 'http://www.w3.org/2000/09/xmldsig#'

SOAP_ACTION = 'runTransaction'
DEFAULT_TIMEOUT_MS = 6000
USER_AGENT = 'CyberSource Python SOAP Toolkit/1.0'
BODY_ID = 'Body'
BINARY_TOKEN_ID = 'X509Token'


class CyberSourceClient:
    """
    Extended SOAP Client with P12 Certificate Token Authentication
    Equivalent in intent to PHP ExtendedClientWithToken class (adapted for Python)
    """

    # Expose namespaces (matching original attribute names for minimal changes)
    WSU_NS = WSU_NS
    WSSE_NS = WSSE_NS
    SOAP_NS = SOAP_NS
    DS_NS = DS_NS

    def __init__(self, wsdl_url, ssl_options=None, timeout_ms=None, debug=False, pretty_xml=False, wire_debug=False):
        """
        Initialize client with WSDL URL and SSL options.

        Args:
            wsdl_url (str): CyberSource WSDL URL (or direct endpoint URL).
            ssl_options (dict): {
                'KEY_ALIAS', 'KEY_FILE', 'KEY_PASS', 'KEY_DIRECTORY'
            } (if None, environment variables are used)
            timeout_ms (int): Request timeout in milliseconds (default 6000).
            debug (bool): Enable detailed diagnostic printing.
            pretty_xml (bool): Pretty print XML when debug is True.
            wire_debug (bool): Enable http.client wire-level debug (very verbose).
        """
        self.wsdl_url = wsdl_url
        self.debug = bool(debug)
        self.pretty_xml = bool(pretty_xml)
        self.wire_debug = bool(wire_debug)
        self.timeout_ms = int(timeout_ms) if timeout_ms is not None else DEFAULT_TIMEOUT_MS

        if self.wire_debug:
            http.client.HTTPConnection.debuglevel = 1  # raw socket-level trace
        else:
            http.client.HTTPConnection.debuglevel = 0

        self.properties_util = PropertiesUtils()
        self.security_util = SecurityUtils()

        # Load SSL options from environment variables if not provided
        if ssl_options is None:
            ssl_options = {
                'KEY_ALIAS': os.environ.get('CYBERSOURCE_KEY_ALIAS') or os.environ.get('KEY_ALIAS'),
                'KEY_FILE': os.environ.get('CYBERSOURCE_KEY_FILE') or os.environ.get('KEY_FILE'),
                'KEY_PASS': os.environ.get('CYBERSOURCE_KEY_PASS') or os.environ.get('KEY_PASS'),
                'KEY_DIRECTORY': os.environ.get('CYBERSOURCE_KEY_DIRECTORY') or os.environ.get('KEY_DIRECTORY')
            }

        self.ssl_options = dict(ssl_options)  # copy to avoid external mutation
        self._enrich_ssl_options()
        self._validate_ssl_options()

        # Parse WSDL URL
        parsed_url = urllib.parse.urlparse(wsdl_url)
        self.host = parsed_url.netloc
        self.scheme = parsed_url.scheme
        raw_path = parsed_url.path or '/'
        # If the path ends with ".wsdl", trim the filename to derive the transactionProcessor endpoint directory
        if raw_path.lower().endswith('.wsdl'):
            # e.g. /commerce/1.x/transactionProcessor/CyberSourceTransaction_1.219.wsdl
            # => /commerce/1.x/transactionProcessor
            parts = raw_path.split('/')
            if len(parts) > 1:
                raw_path = '/'.join(parts[:-1])  # drop last segment (the WSDL file)
            if not raw_path.startswith('/'):
                raw_path = '/' + raw_path
        self.path = raw_path
        self.port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        self.use_ssl = parsed_url.scheme == 'https'

        # Publicly accessible last-call diagnostic fields
        self.last_request_xml = None
        self.last_signed_request_xml = None
        self.last_response_xml = None
        self.last_http_status = None
        self.last_http_reason = None
        self.last_http_headers = None
        self.last_error = None
        self.last_duration_ms = None

        if self.debug:
            self._debug_print("Initialized CyberSourceClient", {
                'endpoint_host': self.host,
                'endpoint_port': self.port,
                'endpoint_path': self.path,
                'scheme': self.scheme,
                'timeout_ms': self.timeout_ms,
                'ssl_options': self._redact_ssl_options(self.ssl_options)
            })

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------
    def run_transaction(self, request_data):
        """
        Run a CyberSource transaction.

        Args:
            request_data (dict): Transaction request data

        Returns:
            dict: Parsed transaction response
        """
        start_time = time.time()
        try:
            # Build SOAP request
            soap_request = self._build_soap_request(request_data)
            self.last_request_xml = soap_request
            if self.debug:
                self._maybe_print_xml(soap_request, "SOAP Request (Unsigned)")

            # Add security headers with P12 authentication
            signed_request = self._add_security_headers(soap_request)
            self.last_signed_request_xml = signed_request
            if self.debug:
                self._maybe_print_xml(signed_request, "SOAP Request (Signed)")

            # Send HTTP request
            response_xml = self._send_http_request(signed_request)
            self.last_response_xml = response_xml
            if self.debug:
                self._maybe_print_xml(response_xml, "SOAP Response")

            # Parse and return response
            parsed = self._parse_response(response_xml)
            return parsed

        except Exception as e:
            self.last_error = e
            if self.debug:
                self._debug_print("run_transaction failed", {'error': str(e)})
            raise
        finally:
            self.last_duration_ms = int((time.time() - start_time) * 1000)

    # -------------------------------------------------------------------------
    # SSL Option Handling
    # -------------------------------------------------------------------------
    def _enrich_ssl_options(self):
        """
        Determine certificate_type (P12 vs PEM) from extension if not set.
        Keeps KEY_ALIAS if provided (even if not used directly yet).
        """
        key_file = self.ssl_options.get('KEY_FILE') or ''
        if 'certificate_type' not in self.ssl_options and key_file:
            ext = os.path.splitext(key_file)[1].lower()
            if ext in ('.p12', '.pfx'):
                self.ssl_options['certificate_type'] = 'P12'
            elif ext in ('.pem', '.crt', '.cer', '.key'):
                self.ssl_options['certificate_type'] = 'PEM'
            else:
                # Default to P12 to align with toolkit migration
                self.ssl_options['certificate_type'] = 'P12'

    def _validate_ssl_options(self):
        """Validate SSL options using PropertiesUtils (raises on failure)."""
        if not self.properties_util.is_valid_file_path(self.ssl_options):
            raise ValueError("Invalid SSL certificate configuration")

    def _redact_ssl_options(self, opts):
        """Return a copy with sensitive values masked for debug output."""
        redacted = {}
        for k, v in opts.items():
            if k in ('KEY_PASS',):
                if isinstance(v, str):
                    redacted[k] = '*' * len(v)
                else:
                    redacted[k] = '***'
            else:
                redacted[k] = v
        return redacted

    # -------------------------------------------------------------------------
    # SOAP Request Construction
    # -------------------------------------------------------------------------
    def _build_soap_request(self, request_data):
        """
        Build SOAP envelope from request data.

        The request structure here is:
            <soap:Envelope>
              <soap:Header/>
              <soap:Body>
                <runTransaction>
                  <request> ... fields ... </request>
                </runTransaction>
              </soap:Body>
            </soap:Envelope>
        """
        envelope = ET.Element('{{{0}}}Envelope'.format(self.SOAP_NS))
        envelope.set('xmlns:soap', self.SOAP_NS)

        # Header (initially empty; security added later)
        ET.SubElement(envelope, '{{{0}}}Header'.format(self.SOAP_NS))

        # Body
        body = ET.SubElement(envelope, '{{{0}}}Body'.format(self.SOAP_NS))

        run_transaction = ET.SubElement(body, 'runTransaction')
        request_elem = ET.SubElement(run_transaction, 'request')

        self._dict_to_xml(request_data, request_elem)

        return ET.tostring(envelope, encoding='unicode')

    def _dict_to_xml(self, data, parent):
        """Convert dictionary to XML elements (Python 3.5 compatible)."""
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

    # -------------------------------------------------------------------------
    # Security / Signing
    # -------------------------------------------------------------------------
    def _add_security_headers(self, soap_request):
        """
        Add WS-Security headers with P12 certificate authentication.
        """
        root = ET.fromstring(soap_request)

        namespaces = {
            'soap': self.SOAP_NS,
            'wsu': self.WSU_NS,
            'wsse': self.WSSE_NS,
            'ds': self.DS_NS
        }

        # Body with wsu:Id
        body = root.find('.//soap:Body', namespaces)
        if body is not None:
            body.set('{{{0}}}Id'.format(self.WSU_NS), BODY_ID)

        # Header (ensure exists)
        header = root.find('.//soap:Header', namespaces)
        if header is None:
            body_index = list(root).index(body) if body is not None else 0
            header = ET.Element('{{{0}}}Header'.format(self.SOAP_NS))
            root.insert(body_index, header)

        # Security element
        security = ET.SubElement(header, '{{{0}}}Security'.format(self.WSSE_NS))
        security.set('xmlns:wsse', self.WSSE_NS)
        security.set('xmlns:wsu', self.WSU_NS)

        cert_path = self.properties_util.get_file_path(self.ssl_options)
        cert_password = self.properties_util.get_certificate_password(self.ssl_options)

        token_element, private_key = self.security_util.generate_security_token(
            root, cert_path, cert_password
        )
        security.append(token_element)

        signature_element = self.security_util.create_signature(
            root, private_key, [BODY_ID]
        )
        security.append(signature_element)

        return ET.tostring(root, encoding='unicode')

    # -------------------------------------------------------------------------
    # HTTP Transport
    # -------------------------------------------------------------------------
    def _send_http_request(self, soap_request):
        """
        Send HTTP request to CyberSource.
        Returns response XML (string). Raises on non-200.
        """
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': SOAP_ACTION,
            'User-Agent': USER_AGENT,
            'Content-Length': str(len(soap_request.encode('utf-8')))
        }

        if self.debug:
            self._debug_print("HTTP Request (pre-send)", {
                'method': 'POST',
                'host': self.host,
                'port': self.port,
                'path': self.path,
                'headers': headers,
                'body_length': len(soap_request)
            })

        if self.use_ssl:
            context = ssl.create_default_context()
            # NOTE: For production you should not disable verification.
            # If required for test environments, you could set:
            # context.check_hostname = False
            # context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(self.host, self.port, context=context, timeout=self._timeout_seconds())
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self._timeout_seconds())

        try:
            conn.request('POST', self.path, soap_request.encode('utf-8'), headers)
            response = conn.getresponse()
            self.last_http_status = response.status
            self.last_http_reason = response.reason
            # Collect headers into a dict
            hdrs = {}
            for k, v in response.getheaders():
                hdrs[k] = v
            self.last_http_headers = hdrs

            response_data = response.read().decode('utf-8', 'replace')

            if self.debug:
                self._debug_print("HTTP Response (received)", {
                    'status': response.status,
                    'reason': response.reason,
                    'headers': hdrs,
                    'body_length': len(response_data)
                })

            if response.status != 200:
                # Always store body before raising
                if self.debug:
                    self._maybe_print_xml(response_data, "HTTP Error Body" if '<' in response_data[:50] else "HTTP Error Raw Body")
                raise Exception('HTTP Error {0}: {1}\n{2}'.format(response.status, response.reason, response_data[:2000]))

            return response_data

        except socket.timeout:
            raise Exception("Request timed out after {0} ms".format(self.timeout_ms))
        finally:
            conn.close()

    def _timeout_seconds(self):
        return max(0.001, self.timeout_ms / 1000.0)

    # -------------------------------------------------------------------------
    # Response Parsing
    # -------------------------------------------------------------------------
    def _parse_response(self, response_xml):
        """
        Parse SOAP response XML into dictionary.
        Mirrors earlier structure (runTransactionResponse -> *reply* element).
        """
        try:
            root = ET.fromstring(response_xml)
        except ET.ParseError as e:
            raise Exception('Failed to parse response XML: {0}'.format(str(e)))

        namespaces = {'soap': self.SOAP_NS}
        body = root.find('.//soap:Body', namespaces)
        if body is None:
            raise Exception('Invalid SOAP response: no Body element found')

        response_elem = None
        for child in body:
            # look for runTransactionResponse
            if 'runTransactionResponse' in child.tag:
                response_elem = child
                break
        if response_elem is None:
            raise Exception('Invalid response: no runTransactionResponse found')

        # find reply element inside response (the first element with 'reply' in its tag)
        reply_elem = None
        for child in response_elem:
            if 'reply' in child.tag:
                reply_elem = child
                break
        if reply_elem is None:
            raise Exception('Invalid response: no reply element found')

        return self._xml_to_dict(reply_elem)

    def _xml_to_dict(self, element):
        """
        Convert XML element to dictionary (Python 3.5 compatible), preserving lists.
        """
        result = {}

        if element.text and element.text.strip():
            if len(element) == 0:
                return element.text.strip()
            else:
                result['_text'] = element.text.strip()

        for child in element:
            tag_name = child.tag.split('}')[-1]
            child_data = self._xml_to_dict(child)
            if tag_name in result:
                if not isinstance(result[tag_name], list):
                    result[tag_name] = [result[tag_name]]
                result[tag_name].append(child_data)
            else:
                result[tag_name] = child_data

        return result

    # -------------------------------------------------------------------------
    # Debug / Utility
    # -------------------------------------------------------------------------
    def _debug_print(self, message, data=None):
        if not self.debug:
            return
        sys.stdout.write("[DEBUG] {0}\n".format(message))
        if data:
            for k in sorted(data.keys()):
                v = data[k]
                # Avoid dumping extremely large bodies fully
                if isinstance(v, str) and len(v) > 1000:
                    sys.stdout.write("    {0}: {1} (truncated {2} chars)\n".format(k, v[:1000], len(v)))
                else:
                    sys.stdout.write("    {0}: {1}\n".format(k, v))

    def _maybe_print_xml(self, xml_string, label):
        if not self.debug:
            return
        if self.pretty_xml:
            try:
                root = ET.fromstring(xml_string)
                self._indent_xml(root)
                pretty = ET.tostring(root, encoding='unicode')
                sys.stdout.write("\n=== {0} ===\n".format(label))
                sys.stdout.write(pretty + "\n")
                sys.stdout.write("=== End {0} ===\n".format(label))
                return
            except Exception:
                # fall back to raw
                pass
        sys.stdout.write("\n=== {0} (Raw) ===\n".format(label))
        sys.stdout.write(xml_string + "\n")
        sys.stdout.write("=== End {0} ===\n".format(label))

    def _indent_xml(self, elem, level=0):
        """
        In-place pretty-print indentation (Python 3.5 compatible).
        """
        i = "\n" + level * "  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            for child in elem:
                self._indent_xml(child, level + 1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i