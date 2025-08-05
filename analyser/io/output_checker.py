import angr
import re

from analyser.can_simulator import Component, Message
from analyser.io.input_tracker import InputTracker
from analyser.io.output_parser import OutputParserRegistry, OutputFunctionParser
from analyser.common import logger, IOState
log = logger(__name__)


class OutputChecker:
    """
    The `OutputChecker` is a middle layer between the component analyser and the `OutputParserRegistry`.
    Its main functionality comes from the `check()` function which checks if a given `angr.SimState` is an
    output function we're tracking. If so, it gets the correct parser for the type of output function and hands over
    to this parser.

    The `check()` function can be used as part of an `action` within an angr breakpoint and for example be called
    everytime before a 'call' within the simulation.
    """

    def __init__(self, component: Component):
        self.component = component
        self.parser_registry = OutputParserRegistry()


    def register_output_function(self, addr: int, name: str):
        """Register a known output function"""
        self.parser_registry.register_function(addr, name)


    def register_parser(self, parser: OutputFunctionParser):
        """Register a custom parser"""
        self.parser_registry.register_parser(parser)


    def check(self, state: angr.SimState, output_func_addrs: list[int]) -> Message | None:
        """
        Check if the current call is to an output function, and if so, extract symbolic arguments.
        Save symbolic outputs into state.globals['output_constraints'].
        """
        call_target = state.inspect.function_address
        concrete_call_target = state.solver.eval(call_target, cast_to=int)
        if concrete_call_target not in output_func_addrs:
            return None

        log.debug(f"Output function called at {hex(concrete_call_target)}")

        # Get the appropriate parser
        parser = self.parser_registry.get_parser(concrete_call_target)
        if parser is None:
            log.warning(f"No parser found for function at {hex(concrete_call_target)}")
            return None

        # Parse arguments using the appropriate parser
        try:
            args = parser.parse_arguments(state)
        except Exception as e:
            log.error(f"Error parsing arguments: {e}")
            return None

        if len(args) != 2:
            log.error(f"Irregular output format {args} for state {hex(state.addr)}")
            return None

        msg_type: IOState = IOState.from_state(args[0], state.copy())
        msg_data: IOState = IOState.from_state(args[1], state.copy())

        if InputTracker.yield_unconstrained:
            self.extract_consumed_ids(self.component, state)

        return Message(self.component.name, msg_type, msg_data)


    @staticmethod
    def extract_consumed_ids(component: Component, state: angr.SimState):
        """
        Try to extract the constraints placed on the input variables and determine if they are
        constrained to a concrete value. Since angr internals sometimes create new variables instead of
        adding constraints to the original one, we have to dynamically look for variables that contain the
        name of a original input and then determine if those are constrained.

        :param component: The component we're working with.
        :param state: The SimState to extract information from.
        :return:
        """
        number_of_inputs = InputTracker.input_counter

        if number_of_inputs == 0:
            log.warning(f"Reached output with no input in {component}. Did we miss an input function type?")
            return

        if number_of_inputs == 1:
            log.debug(f"Reached output with just a single input in {component}. Is it an external sensor?")
            return

        # Look at constraints to find msg_id values (every second input)
        for i in range(0, number_of_inputs, 2):
            var_name = f"{component.name}_input_{i+1}"
            log.debug(f"Looking for constraints on variable: {var_name}")
            log.debug(f"Found {state.solver.constraints}")

            for constraint in state.solver.constraints:
                constraint_str = str(constraint)

                # Look for equality constraints on our variable
                if var_name in constraint_str and '==' in constraint_str:
                    # CHANGE: Capture the full number including 0x prefix if present
                    matches = re.findall(rf'{re.escape(var_name)}\s*==\s*(0x[0-9a-fA-F]+|[0-9]+)', constraint_str)
                    for match in matches:
                        try:
                            # Now match will include '0x' if present
                            if match.startswith('0x'):
                                value = int(match, 16)
                            else:
                                value = int(match, 10)

                            component.add_subscription(value)

                        except ValueError as e:
                            log.error(f"Failed to parse value from {match}: {e}")

                    # Also check for reverse pattern "0x100 == variable"
                    matches = re.findall(rf'(0x[0-9a-fA-F]+|[0-9]+)\s*==\s*{re.escape(var_name)}', constraint_str)
                    for match in matches:
                        try:
                            if match.startswith('0x'):
                                value = int(match, 16)
                            else:
                                value = int(match, 10)

                            component.add_subscription(value)

                        except ValueError as e:
                            log.error(f"Failed to parse value from {match}: {e}")


def setup_output_checker(component: Component, output_addrs) -> OutputChecker:
    """Set up the output checker with known functions"""
    checker = OutputChecker(component)

    for addr, name in output_addrs.items():
        checker.register_output_function(addr, name)
        log.debug(f"Registered {name} at {hex(addr)}")

    return checker