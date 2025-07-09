# refactored_checker.py
import angr
import logging
from analyzer.OutputParser import OutputParserRegistry, OutputFunctionParser

from analyzer.io_state import IOState

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
        if concrete_call_target not in output_func_addrs:
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
            log.error(f"Irregular output format {args} for state {hex(state.addr)}")
            return

        dest: IOState = IOState.from_state(
            f"{self.binary}_out_{hex(concrete_call_target)}_dest",
            args[0],
            state.copy()
        )

        msg_data: IOState = IOState.from_state(
            f"{self.binary}_out_{hex(concrete_call_target)}_msg",
            args[1],
            state.copy()
        )
        msg_data.set_label('symbolic' if msg_data.is_symbolic() else 'concrete')

        callback(dest, msg_data)


def setup_output_checker(binary_path: str, output_addrs) -> OutputChecker:
    """Set up the output checker with known functions"""
    checker = OutputChecker(binary_path)

    for addr, name in output_addrs.items():
        try:
            # Try to resolve function address from PLT
            checker.register_output_function(addr, name)
            log.debug(f"Registered {name} at {hex(addr)}")
        except:
            log.warning(f"Could not find an output parser for {name}")

    return checker