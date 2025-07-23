import angr
import logging
import re

from analyser.input_tracker import InputTracker
from analyser.can_simulator import Component, Message
from analyser.output_parser import OutputParserRegistry, OutputFunctionParser
from analyser.io_state import IOState
log = logging.getLogger(__name__)


class OutputChecker:
    """Main class for checking output function calls"""

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

        if  args[0].symbolic:
            log.critical(f"{self.component} sent a message with symbolic type\n{args[0]}\n")

        msg_id: IOState = IOState.from_state(args[0], state.copy())
        msg_data: IOState = IOState.from_state(args[1], state.copy())


        if msg_data.is_symbolic():
            msg_data.set_label('symbolic' if msg_data.constraints else 'unconstrained')
        else:
            msg_data.set_label('concrete')

        self._extract_subscriptions(state)

        return Message(self.component.cid, msg_id, msg_data)


    def _extract_subscriptions(self, state: angr.SimState):

        number_of_inputs = InputTracker.input_counter

        # Reached output with just a single input.
        # This must be a Sensor / Producer that does not read from the bus.
        # Or this sensor has some issues...
        if number_of_inputs == 0:
            log.warning(f"Reached output with no input in {self.component.name}. Did we miss an input function type?")
            return

        if number_of_inputs == 1:
            log.debug(f"Reached output with just a single input in {self.component.name}. Is it an external sensor?")
            return

        for i in range(0, number_of_inputs, 2):
            if i >= len(InputTracker.flattened_with_context):
                log.warning(f"Component {self.component.name} reached output with uneven number of inputs...")
                break

            msg = InputTracker.flattened_with_context[i]
            msg_id = msg.msg_id

            input_var_name = msg_id.name

            for constraint in state.solver.constraints:
                constraint_str = str(constraint)

                if input_var_name in constraint_str and '==' in constraint_str:
                    matches = re.findall(r'== (?:0x)?([0-9a-fA-F]+)(?:\s|>|$)', constraint_str)
                    for match in matches:
                        try:
                            value = int(match, 16)
                            self.component.subscriptions.add(value)
                            log.info(f"Component appears to read msg_id {value}")
                        except ValueError:
                            pass


def setup_output_checker(component: Component, output_addrs) -> OutputChecker:
    """Set up the output checker with known functions"""
    checker = OutputChecker(component)

    for addr, name in output_addrs.items():
        try:
            # Try to resolve function address from PLT
            checker.register_output_function(addr, name)
            log.debug(f"Registered {name} at {hex(addr)}")
        except:
            log.warning(f"Could not find an output parser for {name}")

    return checker