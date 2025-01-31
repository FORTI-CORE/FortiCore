"""
Utility functions and classes for FortiCore
"""
from .logger import Logger
from .tools import check_and_install_tools, update_tools
from .network import get_ip_address, is_private_ip
from .report_generator import ReportGenerator

__all__ = [
    'Logger',
    'check_and_install_tools',
    'update_tools',
    'get_ip_address',
    'is_private_ip',
    'ReportGenerator'
]
