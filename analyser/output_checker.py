import angr
import logging
import re

import claripy

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

        if InputTracker.yield_unconstrained:
            self._extract_subscriptions(state)

        return Message(self.component.cid, msg_id, msg_data)


    def _extract_subscriptions(self, state: angr.SimState):
        number_of_inputs = InputTracker.input_counter

        if number_of_inputs == 0:
            log.warning(f"Reached output with no input in {self.component.name}. Did we miss an input function type?")
            return

        if number_of_inputs == 1:
            log.debug(f"Reached output with just a single input in {self.component.name}. Is it an external sensor?")
            return

        #Debug state info
        log.error(f"State has {len(state.solver.constraints)} constraints")
        log.error(f"All variables in state: {state.solver.all_variables}")

        # Let's look at the constraints to find our variables
        all_constraint_vars = set()
        for constraint in state.solver.constraints:
            all_constraint_vars.update(constraint.variables)
        log.error(f"All variables in constraints: {all_constraint_vars}")

        # Look at every second input (msg_ids)
        for i in range(0, number_of_inputs, 2):
            # The variable name we're looking for
            var_name = f"{self.component.name}_input_{i+1}"

            log.debug(f"Looking for constraints on variable: {var_name}")

            # Find all variables in the state with this name
            found_var = None
            for var in state.solver.all_variables:
                if var.startswith(var_name):  # startswith because angr might append suffixes
                    found_var = var
                    break

            if not found_var:
                log.warning(f"Could not find variable {var_name} in state")
                continue

            # Create a BV with this variable name to evaluate
            msg_id_bv = claripy.BVS(found_var, Config.default_var_length)

            try:
                if state.solver.unique(msg_id_bv):
                    value = state.solver.eval(msg_id_bv, cast_to=int)
                    self.component.subscriptions.add(value)
                    log.info(f"Component subscribes to msg_id {value}")
                else:
                    possible_values = state.solver.eval_upto(msg_id_bv, 20, cast_to=int)
                    if len(possible_values) < 20:
                        self.component.subscriptions.update(possible_values)
                        log.info(f"Component subscribes to msg_ids {possible_values}")
                    else:
                        log.warning(f"{var_name} appears unconstrained")
            except Exception as e:
                log.error(f"Exception while evaluating {var_name}: {e}")


                """
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
                                """


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