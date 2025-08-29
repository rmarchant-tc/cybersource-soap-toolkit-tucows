#!/usr/bin/env python3
"""
Properties utilities for CyberSource SOAP configuration
Handles certificate path validation and environment variables
"""

import os


class PropertiesUtils:
    """Utilities for handling SSL certificate configuration"""
    
    def is_valid_file_path(self, settings):
        """
        Validate certificate file path and settings
        
        Args:
            settings (dict): SSL settings dictionary
            
        Returns:
            bool: True if valid
            
        Raises:
            ValueError: If configuration is invalid
        """
        key_directory = settings.get('KEY_DIRECTORY')
        key_file = settings.get('KEY_FILE')
        
        if not key_directory or not isinstance(key_directory, str):
            raise ValueError("Key Directory value is missing or empty")
        
        if not key_file or not isinstance(key_file, str):
            raise ValueError("Key File value is missing or empty")
        
        file_path = self._build_file_path(key_directory, key_file)
        
        if not os.path.exists(file_path):
            raise ValueError("Certificate file does not exist: {0}".format(file_path))
        
        if not os.path.isfile(file_path):
            raise ValueError("Certificate path is not a file: {0}".format(file_path))
        
        if not os.access(file_path, os.R_OK):
            raise ValueError("No read permission for certificate file: {0}".format(file_path))
        
        return True
    
    def get_file_path(self, settings):
        """
        Get full path to certificate file
        
        Args:
            settings (dict): SSL settings dictionary
            
        Returns:
            str: Full path to certificate file
        """
        key_directory = settings['KEY_DIRECTORY']
        key_file = settings['KEY_FILE']
        
        return self._build_file_path(key_directory, key_file)
    
    def get_certificate_password(self, settings):
        """
        Get certificate password from settings
        
        Args:
            settings (dict): SSL settings dictionary
            
        Returns:
            str: Certificate password
            
        Raises:
            ValueError: If password is missing
        """
        key_pass = settings.get('KEY_PASS')
        
        if not key_pass or not isinstance(key_pass, str):
            raise ValueError("Certificate password is missing or empty")
        
        return key_pass
    
    def _build_file_path(self, directory, filename):
        """
        Build full file path from directory and filename
        
        Args:
            directory (str): Directory path
            filename (str): File name
            
        Returns:
            str: Full file path
        """
        # Normalize directory path (remove trailing separators)
        normalized_dir = directory.rstrip(os.sep)
        
        # Join with filename
        return os.path.join(normalized_dir, filename)