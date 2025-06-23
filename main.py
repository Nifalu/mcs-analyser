from analyzer.MCSAnalyser import mainA
from utils.logger import logger, set_project_log_level, set_dependency_log_level
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
set_project_log_level(DEBUG)
set_dependency_log_level(ERROR)
log = logger(__name__)
from analyzer.coordinator import Coordinator

from pathlib import Path
import os

COMPONENTS_DIR = Path(__file__).parent / "bin"

COMPONENT_DICT = {
    1: 'c1',
    2: 'c2',
    3: 'c3',
    4: 'c4',
    5: 'c5',
}

def get_component_paths() -> list[Path]:
    """
    Load all components from the 'components' directory.
    """
    if not COMPONENTS_DIR.exists():
        log.error(f"Components directory {COMPONENTS_DIR} does not exist.")
        return []

    components = []
    for f in COMPONENTS_DIR.iterdir():
        if f.is_file() and os.access(f, os.X_OK):
            components.append(f)
            log.info(f"Loaded component: {f}")

    return components



def main():
    #co = Coordinator()
    #co.run()
    mainA()




















if __name__ == "__main__":
    main()