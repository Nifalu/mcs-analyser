import logging
from rich.logging import RichHandler

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

# Set logging for specific angr-related packages
for module in [
    "angr",
    "cle",
    "pyvex",
    "archinfo",
    "ailment",
    "claripy",
]:
    logging.getLogger(module).setLevel(logging.ERROR)


def logger(name, level=logging.NOTSET) -> logging.Logger:
    log = logging.getLogger(name)
    log.setLevel(level)
    return log