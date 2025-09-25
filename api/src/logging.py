"""
    This file defines the logging related components of CFCO

    Again, fair deal of this is clanker code
"""
import os
import sys
import logging
from fastapi import Request

from .consts import LoggingConsts, BUILD_DIR

def setup_global_logger() -> logging.Logger:
    """
        Setup the global logger that prints to screen and global log file
    """
    # Create a named logger for global logging (not root logger)
    global_logger = logging.getLogger(LoggingConsts.name)
    global_logger.setLevel(logging.DEBUG)
    
    # Clear any existing handlers to avoid duplicates
    global_logger.handlers.clear()
    
    # Prevent propagation to root logger to avoid interference
    global_logger.propagate = False
    
    # Create console handler for screen output
    c_handler = logging.StreamHandler(sys.stdout) 
    c_handler.setLevel(logging.DEBUG)
    c_handler.setFormatter(LoggingConsts.c_formatter)
    global_logger.addHandler(c_handler)
   
    # Create file handler for global log file
    f_handler = logging.FileHandler(LoggingConsts.g_logfile, 'a', 'utf-8')
    f_handler.setLevel(logging.DEBUG)
    f_handler.setFormatter(LoggingConsts.f_formatter)
    global_logger.addHandler(f_handler)
    
    return global_logger

def setup_uvicorn_loggers():
    """
        Configure uvicorn loggers separately
    """
    # Configure Uvicorn loggers to use our global logger's handlers
    uvicorn_logger = logging.getLogger("uvicorn")
    uvicorn_logger.setLevel(logging.INFO)
    uvicorn_logger.propagate = False
    
    # Add global logger's handlers to uvicorn logger
    global_logger = logging.getLogger(LoggingConsts.name)
    for handler in global_logger.handlers:
        uvicorn_logger.addHandler(handler)
    
    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    uvicorn_access_logger.setLevel(logging.INFO)
    uvicorn_access_logger.propagate = False
    
    # Add global logger's handlers to uvicorn access logger
    for handler in global_logger.handlers:
        uvicorn_access_logger.addHandler(handler)

# Initialize global logger
GlobalLogger = setup_global_logger()
setup_uvicorn_loggers()

def log_request(req: Request) -> None:
    """
    Log incoming request into a file
    """
    val = ""
    for k, v in req.headers.items():
        val = val + f"{k}: {v}, "
    val = (val.strip())[:-1]
    GlobalLogger.info("%s - %s %s", val.strip(), req.method, req.url)

class PerRequestLogger:
    def __init__(self, buildid):
        """Create a logger for each incoming request"""
        self.buildid = buildid
        self.local_log = os.path.join(BUILD_DIR, buildid, LoggingConsts.l_logfile)
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(self.local_log), exist_ok=True)
        
        # Create a unique logger name to avoid conflicts
        logger_name = f"{LoggingConsts.name}.{buildid}"
        self.local_logger = logging.getLogger(logger_name)
        
        # Only configure if not already configured (avoid duplicate handlers)
        if not self.local_logger.handlers:
            # Set logging level
            self.local_logger.setLevel(logging.DEBUG)
            
            # Prevent propagation to avoid duplicate logs
            self.local_logger.propagate = False
           
            # Create file handler for local log
            f_handler = logging.FileHandler(self.local_log, 'a', 'utf-8')
            f_handler.setLevel(logging.DEBUG)
            f_handler.setFormatter(LoggingConsts.f_formatter)
            self.local_logger.addHandler(f_handler)
        
        # Reference to global logger
        self.global_logger = GlobalLogger

    def debug(self, msg, *args, **kwargs):
        """Log debug message to both local and global loggers"""
        self.local_logger.debug(msg, *args, **kwargs)
        self.global_logger.debug(f"[{self.buildid}] {msg}", *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        """Log info message to both local and global loggers"""
        self.local_logger.info(msg, *args, **kwargs)
        self.global_logger.info(f"[{self.buildid}] {msg}", *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """Log warning message to both local and global loggers"""
        self.local_logger.warning(msg, *args, **kwargs)
        self.global_logger.warning(f"[{self.buildid}] {msg}", *args, **kwargs)

    def warn(self, msg, *args, **kwargs):
        """Alias for warning (for backward compatibility)"""
        self.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """Log error message to both local and global loggers"""
        self.local_logger.error(msg, *args, **kwargs)
        self.global_logger.error(f"[{self.buildid}] {msg}", *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        """Log critical message to both local and global loggers"""
        self.local_logger.critical(msg, *args, **kwargs)
        self.global_logger.critical(f"[{self.buildid}] {msg}", *args, **kwargs)

    def exception(self, msg, *args, exc_info=True, **kwargs):
        """Log exception message to both local and global loggers"""
        self.local_logger.exception(msg, *args, exc_info=exc_info, **kwargs)
        self.global_logger.exception(f"[{self.buildid}] {msg}", *args, exc_info=exc_info, **kwargs)

    def cleanup(self):
        """Clean up handlers to prevent memory leaks"""
        for handler in self.local_logger.handlers[:]:
            handler.close()
            self.local_logger.removeHandler(handler)
