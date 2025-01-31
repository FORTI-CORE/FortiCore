import socket
import ipaddress
from ..utils.logger import Logger

logger = Logger.get_logger(__name__)

def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        logger.error(f"Error fetching IP address: {e}")
        return None

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError as e:
        logger.error(f"Invalid IP address: {e}")
        return False 