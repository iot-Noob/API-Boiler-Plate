# App/core/logging.py (Simple version)
import logging
import os
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

def setup_core_logging():
    """Setup logging for the core module"""
    # Get log path from environment or use default
    try:
        from App.GetEnvDate import log_path
        LOG_PATH = log_path if log_path else "logs"
    except (ImportError, AttributeError):
        LOG_PATH = "logs"
    
    # Create log directory
    log_dir = Path(LOG_PATH)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / "core.log"
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # File handler
    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(
        logging.Formatter('%(levelname)s - %(name)s - %(message)s')
    )
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Log initialization
    logger.info(f"Core logging initialized. File: {log_file}")
    
    return logger

# Initialize when module is imported
core_logger = setup_core_logging()

def get_core_logger(name: str = "App.core") -> logging.Logger:
    """Get a logger for core modules"""
    return logging.getLogger(name)