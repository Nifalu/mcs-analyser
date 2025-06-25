import logging
from rich.logging import RichHandler

# Project-level log level (default = NOTSET; change via set_project_log_level)
_PROJECT_LOG_LEVEL = logging.NOTSET

FORMAT = "%(message)s"
logging.basicConfig(
    level=_PROJECT_LOG_LEVEL,  # Only affects root logger
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

    # Optionally, propagate to all existing loggers under your project namespace
    for name, log in logging.root.manager.loggerDict.items():
        if name.startswith("your_project"):  # Change to your actual top-level module name
            log.setLevel(level)

def logger(name: str) -> logging.Logger:
    """Return a logger with project-level default log level."""
    log = logging.getLogger(name)
    log.setLevel(_PROJECT_LOG_LEVEL)
    return log
