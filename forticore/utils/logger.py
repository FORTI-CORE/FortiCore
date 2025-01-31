import logging
from pathlib import Path

class Logger:
    _instance = None
    
    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        if Logger._instance is None:
            Logger._instance = logging.getLogger(name)
            Logger._setup_logger()
        return Logger._instance
    
    @staticmethod
    def _setup_logger():
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # File handler
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "forticore.log")
        file_handler.setFormatter(formatter)
        
        Logger._instance.addHandler(console_handler)
        Logger._instance.addHandler(file_handler)
        Logger._instance.setLevel(logging.INFO)
