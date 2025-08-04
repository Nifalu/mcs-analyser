"""
This module provides general utility functions.
"""
from analyser.common.logger import logger
log = logger(__name__)

def extract_msg_id_map(binary_path, prefix) -> dict[int, str]:
    """
    Extracts the message type => id map from a binary file.
    This is mainly used to enrich logging statements and visualisation info as strings are easier to read
    than plain numbers.

    :param binary_path:
    :param prefix:
    :return:
    """
    import angr
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
    except Exception as e:
        log.error(f"Error loading binary: {e} during symbol extraction")
        return {}

    log.debug(f"Loaded binary: {binary_path}")

    results = {}

    for symbol in proj.loader.main_object.symbols:
        if not symbol.name:
            continue

        clean_name = symbol.name.lstrip('_')
        if clean_name.startswith(prefix):
            if hasattr(symbol, 'size') and symbol.size > 0:
                value = proj.loader.memory.unpack_word(symbol.rebased_addr, size=8)
                log.info(f"Extracted {clean_name} = {value} (0x{value:x})") 
                if value in results:
                    raise(ValueError(f"Multiple Message ID's with the same name detected: {value}"))
                results[value] = clean_name
    return results