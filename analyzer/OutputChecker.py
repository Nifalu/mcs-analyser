# refactored_checker.py
import angr
import logging
from analyzer.OutputParser import OutputParserRegistry, OutputFunctionParser

from analyzer.coordinator import \
    CANMessage
from analyzer.io_state import \
    IOState

log = logging.getLogger(__name__)


class OutputChecker:
    """Main class for checking output function calls"""

    def __init__(self, binary: str):
        self.binary = binary
        self.parser_registry = OutputParserRegistry()

    def register_output_function(self, addr: int, name: str):
        """Register a known output function"""
        self.parser_registry.register_function(addr, name)

    def register_parser(self, parser: OutputFunctionParser):
        """Register a custom parser"""
        self.parser_registry.register_parser(parser)

    def check_output(self, state: angr.SimState, output_func_addrs: list[int], callback) -> None:
        """
        Check if the current call is to an output function, and if so, extract symbolic arguments.
        Save symbolic outputs into state.globals['output_constraints'].
        """
        call_target = state.inspect.function_address
        concrete_call_target = state.solver.eval(call_target, cast_to=int)
        log.debug(f"Checking if {hex(concrete_call_target)} is in {[hex(x) for x in output_func_addrs]}")

        if concrete_call_target not in output_func_addrs:
            log.debug(f"It is not. Skipping...")
            return

        log.debug(f"Output function called at {hex(concrete_call_target)}")

        # Get the appropriate parser
        parser = self.parser_registry.get_parser(concrete_call_target)
        if parser is None:
            log.warning(f"No parser found for function at {hex(concrete_call_target)}")
            return

        # Parse arguments using the appropriate parser
        try:
            args = parser.parse_arguments(state)
        except Exception as e:
            log.error(f"Error parsing arguments: {e}")
            return

        if len(args) != 2:
            log.error(f"Irregular output format {args}")
            return

        dest: IOState = IOState.from_state(
            f"{self.binary}_out_{hex(concrete_call_target)}_dest",
            args[0],
            state.copy()
        )

        msg_data: IOState = IOState.from_state(
            f"{self.binary}_out_{hex(concrete_call_target)}_msg",
            args[1],
            state
        )

        can_msg = CANMessage(
            dest=dest,
            msg_data=msg_data,
        )

        callback(can_msg)


# Example usage:
def setup_output_checker(binary_path: str, output_addrs) -> OutputChecker:
    """Set up the output checker with known functions"""
    checker = OutputChecker(binary_path)

    for name, addr in output_addrs.items():
        try:
            # Try to resolve function address from PLT
            checker.register_output_function(addr, name)
            log.info(f"Registered {name} at {hex(addr)}")
        except:
            log.debug(f"Could not resolve {name}")

    return checker