"""
CyberSource Python SOAP Toolkit
Compatible with Debian Stretch and Python 3.5+

This toolkit provides P12 certificate-based authentication for CyberSource SOAP API.
"""

from .client import CyberSourceClient
from .config import PropertiesUtils

__version__ = "1.0.0"
__author__ = "CyberSource"
__email__ = "developer@cybersource.com"

__all__ = ["CyberSourceClient", "PropertiesUtils"]

# Python 3.5 compatibility check
import sys
if sys.version_info < (3, 5):
    raise ImportError("Python 3.5 or higher is required")

# Check for required dependencies
try:
    import xml.etree.ElementTree
except ImportError:
    raise ImportError("xml.etree.ElementTree is required but not available")

try:
    import http.client
except ImportError:
    raise ImportError("http.client is required but not available")

try:
    import ssl
except ImportError:
    raise ImportError("ssl module is required but not available")
