"""
Command Line Interface module for FortiCore
"""
from .terminal import FortiCoreTerminal
from .commands import CommandHandler

__all__ = ['FortiCoreTerminal', 'CommandHandler']
