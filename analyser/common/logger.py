"""
Configuration of a nice looking logger :)
"""

import logging
from rich.logging import RichHandler

_PROJECT_LOG_LEVEL = logging.INFO

FORMAT = "%(message)s"
logging.basicConfig(
    level=_PROJECT_LOG_LEVEL,
    format=FORMAT,
    datefmt="[%X]",
    handlers=[RichHandler(show_path=False)],
)

def set_dependency_log_level(level: int):
    for dep in ["angr", "cle", "pyvex", "archinfo", "ailment", "claripy"]:
        logging.getLogger(dep).setLevel(level)

def set_project_log_level(level: int):
    """Set global log level for all project loggers."""
    global _PROJECT_LOG_LEVEL
    _PROJECT_LOG_LEVEL = level
    logging.getLogger().setLevel(level)


def logger(name: str, level=_PROJECT_LOG_LEVEL) -> logging.Logger:
    """Return a logger with project-level default log level."""
    log = logging.getLogger(name)
    log.setLevel(level)
    return log
