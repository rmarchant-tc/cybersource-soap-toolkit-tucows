#!/usr/bin/env python3
"""
Security utilities for CyberSource SOAP authentication
Handles P12 certificate loading, XML signing, and canonicalization
Compatible with multiple cryptography library versions
"""

import os
import base64
import hashlib
import tempfile
import subprocess
from xml.etree import ElementTree as ET

try:
    # Try modern cryptography library first
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
    
    # Check if backend parameter is needed (older versions)
    import inspect
    load_key_signature = inspect.signature(pkcs12.load_key_and_certificates)
    NEEDS_BACKEND = 'backend' in load_key_signature.parameters
    
except ImportError:
    HAS_CRYPTOGRAPHY = False
    NEEDS_BACKEND = False

try:
    # Fallback to PyOpenSSL
    from OpenSSL import crypto
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False


class SecurityUtils:
    """Security utilities for P12 certificate handling and XML signing"""
    
    # WS-Security namespaces
    WSU_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
    WSSE_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
    
    def generate_security_token(self, xml_doc, cert_path, cert_password):
        """
        Generate Binary Security Token from P12 certificate
        
        Args:
            xml_doc (Element): XML document
            cert_path (str): Path to P12 certificate
            cert_password (str): Certificate password
            
        Returns:
            tuple: (token_element, private_key)
        """
        # Load certificate and private key
        cert_data, private_key = self._load_p12_certificate(cert_path, cert_password)
        
        # Create Binary Security Token element
        token = ET.Element('{{{0}}}BinarySecurityToken'.format(self.WSSE_NS))
        token.set('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3')
        token.set('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary')
        token.set('{{{0}}}Id'.format(self.WSU_NS), 'X509Token')
        token.text = cert_data
        
        return token, private_key
    
    def _load_p12_certificate(self, cert_path, password):
        """
        Load P12 certificate and extract public cert and private key
        
        Args:
            cert_path (str): Path to P12 file
            password (str): Certificate password
            
        Returns:
            tuple: (base64_cert_data, private_key_data)
        """
        if HAS_CRYPTOGRAPHY:
            return self._load_with_cryptography(cert_path, password)
        elif HAS_PYOPENSSL:
            return self._load_with_pyopenssl(cert_path, password)
        else:
            return self._load_with_openssl_command(cert_path, password)
    
    def _load_with_cryptography(self, cert_path, password):
        """Load P12 using cryptography library with version compatibility"""
        with open(cert_path, 'rb') as f:
            p12_data = f.read()
        
        try:
            # Try with backend parameter for older versions
            if NEEDS_BACKEND:
                private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                    p12_data, password.encode('utf-8'), backend=default_backend()
                )
            else:
                # Newer versions don't need backend parameter
                private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                    p12_data, password.encode('utf-8')
                )
        except TypeError as e:
            if "backend" in str(e):
                # Fallback: try without backend if it failed with backend
                try:
                    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                        p12_data, password.encode('utf-8')
                    )
                except TypeError:
                    # If still failing, try with backend
                    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                        p12_data, password.encode('utf-8'), backend=default_backend()
                    )
            else:
                raise
        
        # Convert certificate to base64
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode('ascii')
        
        # Get private key in PEM format for signing
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return cert_b64, private_key_pem
    
    def _load_with_pyopenssl(self, cert_path, password):
        """Load P12 using PyOpenSSL library"""
        with open(cert_path, 'rb') as f:
            p12_data = f.read()
        
        p12 = crypto.load_pkcs12(p12_data, password.encode('utf-8'))
        certificate = p12.get_certificate()
        private_key = p12.get_privatekey()
        
        # Convert certificate to base64
        cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)
        cert_b64 = base64.b64encode(cert_der).decode('ascii')
        
        # Get private key in PEM format
        private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
        
        return cert_b64, private_key_pem
    
    def _load_with_openssl_command(self, cert_path, password):
        """
        Fallback: Load P12 using system openssl command
        For Debian Stretch compatibility
        """
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as cert_file:
            cert_temp_path = cert_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
            key_temp_path = key_file.name
        
        try:
            # Extract certificate
            cert_cmd = [
                'openssl', 'pkcs12', '-in', cert_path,
                '-clcerts', '-nokeys', '-out', cert_temp_path,
                '-passin', 'pass:{0}'.format(password)
            ]
            subprocess.check_call(cert_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Extract private key
            key_cmd = [
                'openssl', 'pkcs12', '-in', cert_path,
                '-nocerts', '-nodes', '-out', key_temp_path,
                '-passin', 'pass:{0}'.format(password)
            ]
            subprocess.check_call(key_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Read certificate and convert to base64
            with open(cert_temp_path, 'r') as f:
                cert_pem = f.read()
            
            # Extract DER data from PEM
            cert_lines = cert_pem.split('\n')
            cert_data_lines = []
            in_cert = False
            
            for line in cert_lines:
                if '-----BEGIN CERTIFICATE-----' in line:
                    in_cert = True
                    continue
                elif '-----END CERTIFICATE-----' in line:
                    break
                elif in_cert:
                    cert_data_lines.append(line.strip())
            
            cert_b64 = ''.join(cert_data_lines)
            
            # Read private key
            with open(key_temp_path, 'r') as f:
                private_key_pem = f.read().encode('utf-8')
            
            return cert_b64, private_key_pem
            
        finally:
            # Clean up temporary files
            if os.path.exists(cert_temp_path):
                os.unlink(cert_temp_path)
            if os.path.exists(key_temp_path):
                os.unlink(key_temp_path)
    
    def create_signature(self, xml_doc, private_key, element_ids):
        """
        Create XML digital signature
        
        Args:
            xml_doc (Element): XML document
            private_key (bytes): Private key data
            element_ids (list): List of element IDs to sign
            
        Returns:
            Element: Signature element
        """
        # Create Signature element
        signature = ET.Element('{{{0}}}Signature'.format(self.DS_NS))
        
        # Create SignedInfo
        signed_info = self._build_signed_info(xml_doc, element_ids)
        signature.append(signed_info)
        
        # Sign the SignedInfo
        signed_info_c14n = self._canonicalize_element(signed_info)
        signature_value = self._sign_data(signed_info_c14n, private_key)
        
        # Add SignatureValue
        sig_value = ET.Element('{{{0}}}SignatureValue'.format(self.DS_NS))
        sig_value.text = base64.b64encode(signature_value).decode('ascii')
        signature.append(sig_value)
        
        # Add KeyInfo
        key_info = ET.Element('{{{0}}}KeyInfo'.format(self.DS_NS))
        sec_token_ref = ET.SubElement(key_info, '{{{0}}}SecurityTokenReference'.format(self.WSSE_NS))
        reference = ET.SubElement(sec_token_ref, '{{{0}}}Reference'.format(self.WSSE_NS))
        reference.set('URI', '#X509Token')
        signature.append(key_info)
        
        return signature
    
    def _build_signed_info(self, xml_doc, element_ids):
        """Build SignedInfo element for digital signature"""
        signed_info = ET.Element('{{{0}}}SignedInfo'.format(self.DS_NS))
        
        # Canonicalization Method
        c14n_method = ET.SubElement(signed_info, '{{{0}}}CanonicalizationMethod'.format(self.DS_NS))
        c14n_method.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')
        
        # Signature Method
        sig_method = ET.SubElement(signed_info, '{{{0}}}SignatureMethod'.format(self.DS_NS))
        sig_method.set('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
        
        # References
        for element_id in element_ids:
            element = self._find_element_by_id(xml_doc, element_id)
            if element is not None:
                # Canonicalize the element
                element_c14n = self._canonicalize_element(element)
                
                # Calculate digest
                digest = hashlib.sha256(element_c14n.encode('utf-8')).digest()
                
                # Create Reference element
                reference = ET.SubElement(signed_info, '{{{0}}}Reference'.format(self.DS_NS))
                reference.set('URI', '#{0}'.format(element_id))
                
                # Transforms
                transforms = ET.SubElement(reference, '{{{0}}}Transforms'.format(self.DS_NS))
                transform = ET.SubElement(transforms, '{{{0}}}Transform'.format(self.DS_NS))
                transform.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')
                
                # Digest Method
                digest_method = ET.SubElement(reference, '{{{0}}}DigestMethod'.format(self.DS_NS))
                digest_method.set('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256')
                
                # Digest Value
                digest_value = ET.SubElement(reference, '{{{0}}}DigestValue'.format(self.DS_NS))
                digest_value.text = base64.b64encode(digest).decode('ascii')
        
        return signed_info
    
    def _find_element_by_id(self, xml_doc, element_id):
        """Find element by wsu:Id attribute"""
        for elem in xml_doc.iter():
            id_attr = elem.get('{{{0}}}Id'.format(self.WSU_NS))
            if id_attr == element_id:
                return elem
        return None
    
    def _canonicalize_element(self, element):
        """
        Canonicalize XML element
        Simplified canonicalization for Python 3.5 compatibility
        """
        # Convert element to string
        xml_str = ET.tostring(element, encoding='unicode')
        
        # Basic canonicalization (remove extra whitespace, normalize)
        # This is a simplified version - for production, use proper C14N
        lines = []
        for line in xml_str.split('\n'):
            line = line.strip()
            if line:
                lines.append(line)
        
        return ''.join(lines)
    
    def _sign_data(self, data, private_key_pem):
        """
        Sign data with private key with version compatibility
        
        Args:
            data (str): Data to sign
            private_key_pem (bytes): Private key in PEM format
            
        Returns:
            bytes: Signature
        """
        if HAS_CRYPTOGRAPHY:
            return self._sign_with_cryptography(data, private_key_pem)
        elif HAS_PYOPENSSL:
            return self._sign_with_pyopenssl(data, private_key_pem)
        else:
            return self._sign_with_openssl_command(data, private_key_pem)
    
    def _sign_with_cryptography(self, data, private_key_pem):
        """Sign using cryptography library with version compatibility"""
        try:
            # Try loading private key with backend parameter (older versions)
            if NEEDS_BACKEND:
                private_key = serialization.load_pem_private_key(
                    private_key_pem, password=None, backend=default_backend()
                )
            else:
                # Newer versions don't need backend
                private_key = serialization.load_pem_private_key(
                    private_key_pem, password=None
                )
        except TypeError as e:
            if "backend" in str(e):
                # Try the other way if backend parameter failed
                if NEEDS_BACKEND:
                    private_key = serialization.load_pem_private_key(
                        private_key_pem, password=None
                    )
                else:
                    private_key = serialization.load_pem_private_key(
                        private_key_pem, password=None, backend=default_backend()
                    )
            else:
                raise
        
        signature = private_key.sign(
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return signature
    
    def _sign_with_pyopenssl(self, data, private_key_pem):
        """Sign using PyOpenSSL"""
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)
        signature = crypto.sign(private_key, data.encode('utf-8'), 'sha256')
        return signature
    
    def _sign_with_openssl_command(self, data, private_key_pem):
        """Sign using system openssl command"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
            key_file.write(private_key_pem.decode('utf-8'))
            key_path = key_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as data_file:
            data_file.write(data)
            data_path = data_file.name
        
        with tempfile.NamedTemporaryFile(mode='rb', delete=False) as sig_file:
            sig_path = sig_file.name
        
        try:
            cmd = [
                'openssl', 'dgst', '-sha256', '-sign', key_path,
                '-out', sig_path, data_path
            ]
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            with open(sig_path, 'rb') as f:
                signature = f.read()
            
            return signature
            
        finally:
            for path in [key_path, data_path, sig_path]:
                if os.path.exists(path):
                    os.unlink(path)