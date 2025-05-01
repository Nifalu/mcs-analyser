from logger import logger
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
from rich import print
from io_state import IOState, IOSnapshot

import \
    angr
from angr import \
    SimulationManager, \
    SimState

import re

BINARY = "./bin/test_x86"
INTERESTING_INPUTS = ['scanf', 'gets', 'read']
INTERESTING_OUTPUTS = ['printf', 'puts', 'write']

log = logger("SimpleAnalyzer", level=DEBUG)


class SimpleAnalyzer:

    """
    Have some hooks to track the IO operations.
    """

    class InputHook(angr.SimProcedure):
        def __init__(self, inputs):
            super().__init__()
            self.inputs = inputs


        def run(self, fmt, ptr):
            input_count = self.state.globals.get('input_count', 0)

            if input_count < len(self.inputs):
                ios = self.inputs[input_count]
                bv = ios.bv
                bv_name = ios.name
                if ios.constraints:
                    self.state.solver.add(*ios.constraints)
                log.info(f"Using input {input_count} for {bv_name}: {bv}")
            else:
                log.warning(f"Input count ({input_count}) exceeds number of passed inputs ({len(self.inputs)}). Using default input.")
                bv_name = f"auto_input_{input_count}"
                bv = self.state.solver.BVS(bv_name, 32)


            # store the value in the memory location pointed to by ptr
            self.state.memory.store(ptr, bv, endness=self.state.arch.memory_endness)

            if 'inputs' not in self.state.globals:
                self.state.globals['inputs'] = []
            self.state.globals['inputs'].append((bv_name, bv))

            self.state.globals['input_count'] = input_count + 1

            return 1


    def __init__(self, binary: str, inputs: list[IOState]) -> None:
        """
        Initialize the SimpleAnalyzer with the binary to analyze.
        :param binary: Path to the binary file.
        """
        self.binary = binary
        self.inputs = inputs
        self.proj = angr.Project(self.binary, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGEmulated()



    @staticmethod
    def build_regex_pattern(list_of_names: list[str]) -> re.Pattern:
        """
        Build a regex pattern from a list of function names.
        :param list_of_names:
        :return:
        """
        # Escape special characters in function names
        escaped_names = [re.escape(name) for name in list_of_names]
        # Join the escaped names with '|' to create an OR pattern
        pattern = '|'.join(escaped_names)
        return re.compile(pattern)

    def hook_interesting_functions(self,
            in_funcs: list[int]) -> None:
        """
        Hook interesting functions in the binary
        :return: set of input and output function addresses
        """
        for addr in in_funcs:
            self.proj.hook(addr, self.InputHook(self.inputs)) if not self.proj.is_hooked(addr) else None


    def find_interesting_functions(self,
            interesting_input_funcs=None,
            interesting_output_funcs=None) -> (set[int], set[int]):
        """
        Hook interesting functions in the binary or use the default ones.
        :param interesting_input_funcs:
        :param interesting_output_funcs:
        :return: set of input and output function addresses
        """

        # if no interesting inputs or outputs are provided, use the default ones
        if interesting_input_funcs is None:
            interesting_input_funcs = INTERESTING_INPUTS
        if interesting_output_funcs is None:
            interesting_output_funcs = INTERESTING_OUTPUTS

        # Create regex patterns for the interesting functions
        input_func_pattern = SimpleAnalyzer.build_regex_pattern(interesting_input_funcs)
        output_func_pattern = SimpleAnalyzer.build_regex_pattern(interesting_output_funcs)

        # Retrieve the interesting function addresses
        input_funcs = self._find_function_addresses(input_func_pattern)
        output_funcs = self._find_function_addresses(output_func_pattern)

        # Warn if too many functions are found.
        if len(input_funcs) > 5:
            log.warning("Found a lot of input functions...")
        if len(output_funcs) > 5:
            log.warning("Found a lot of output functions...")

        return input_funcs, output_funcs


    def _find_function_addresses(self, pattern: re.Pattern) -> set[int]:
        """
        Pass a list of function names to find in the binary.
        :param pattern:
        :return: Set of function addresses
        """
        found_funcs = set()

        log.info(f"Searching for functions matching pattern: {pattern.pattern}")

        for func in self.cfg.kb.functions.values():
            if func.name and pattern.search(func.name):
                log.info(f"{func.name.ljust(15)} at {func.addr:#x}")
                found_funcs.add(func.addr)

        if not found_funcs:
            log.warning(f"No function addresses found matching pattern {pattern.pattern}")
        return found_funcs

    def capture_call_states(self, func_addr: int) -> list[angr.SimState]:
        """
        :param func_addr:
        :return: list of SimState objects
        """
        initial_state: SimState = self.proj.factory.entry_state()
        simgr: SimulationManager = self.proj.factory.simgr(initial_state)

        log.info(f"Capturing call states for function at {func_addr:#x}")
        log.info(f"Exploring from {initial_state.addr:#x} to {func_addr:#x}")

        simgr.explore(find=func_addr, cfg=self.cfg)

        if not simgr.found:
            log.warning(f"Could not reach function addr at {func_addr:#x}")
        else:
            log.info(f"Found {len(simgr.found)} states that call {func_addr:#x}")
        return simgr.found


    def find_all_solutions(self, entry_state: SimState, targets: list[int], max_solutions: int = 5) -> set[SimState]:
        """
        Find all solutions to the binary that lead to a specific output.
        :param targets:
        :param max_solutions:
        :param entry_state: initial state of the binary
        :return: None
        """

        entry_state.inspect.b(
            'call',
            when=angr.BP_BEFORE,
            action=lambda state: self.check_output(state, targets)
        )

        simgr: SimulationManager = self.proj.factory.simgr(entry_state)

        log.info(f"Finding all solutions from {entry_state.addr:#x}")

        simgr.explore(
            find=targets,
            cfg=self.cfg,
            num_find=max_solutions,
        )

        log.info(f"Found {len(simgr.found)} solutions")

        if len(simgr.found) == max_solutions:
            log.warning(f"Found {max_solutions} solutions, consider increasing the max_solutions parameter.")

        solutions = set()

        for i, found_state in enumerate(simgr.found):
            if 'inputs' in found_state.globals and found_state.globals['inputs']:
                solutions.add(found_state)

        return solutions

    def check_output(self, state: angr.SimState, output_func_addrs: list[int]) -> None:
        """
        Check if the current call is to an output function, and if so, extract symbolic arguments.
        Save symbolic outputs into state.globals['output_constraints'].
        """

        call_target = state.inspect.function_address  # address of the function being called
        concrete_call_target = state.solver.eval(call_target, cast_to=int)
        log.debug(f"Checking if {concrete_call_target} is in {output_func_addrs}")

        if concrete_call_target not in output_func_addrs:
            log.debug(f"It is not. Skipping...")
            return  # not an interesting output function

        log.info(f"Output function called at {concrete_call_target:#x}")

        arch_name = state.arch.name.lower()

        if 'x86' in arch_name:
            #format_str_ptr = state.memory.load(state.regs.esp + 4, state.arch.bytes)
            output_value = state.memory.load(state.regs.esp + 8, state.arch.bytes)
        elif 'amd64' in arch_name:
            #format_str_ptr = state.regs.rdi
            output_value = state.regs.rsi
        else:
            log.warning(f"Architecture {arch_name} not handled for argument fetching.")
            return


        if state.solver.symbolic(output_value):
            log.info(f"Output argument is symbolic! Expr: {output_value}")
            if 'output_constraints' not in state.globals:
                state.globals['output_constraints'] = []
            state.globals['output_constraints'].append(
                (f'output_{concrete_call_target:x}', output_value)
            )
        else:
            concrete_val = state.solver.eval(output_value, cast_to=int)
            log.info(f"Output argument is concrete: {concrete_val}")
            if 'output_constraints' not in state.globals:
                state.globals['output_constraints'] = []
            state.globals['output_constraints'].append(
                (f'output_{concrete_call_target:x}', output_value)
            )

        if 'io_states' not in state.globals:
                state.globals['io_states'] = []
        try:
            ios = IOState.from_state(f"output_{concrete_call_target:x}", output_value, state)
            state.globals['io_states'].append(ios)
            log.info(f"Captured IOState: {ios}")
        except ValueError as e:
            log.exception(f"Error creating IOState:", e)
            return


def main():

    # Have an unconstrained input (IOState)

    initial_input = IOState.unconstrained("input", 32)

    sa = SimpleAnalyzer(BINARY, [initial_input])
    in_addrs, out_addrs = sa.find_interesting_functions()
    sa.hook_interesting_functions(in_addrs)

    snapshot = IOSnapshot("Component A")
    snapshot.add_input(initial_input)

    for addr in in_addrs:
        call_states = sa.capture_call_states(addr)
        for state in call_states:
            solutions = sa.find_all_solutions(state, out_addrs, max_solutions=10)
            for i, found_state in enumerate(solutions):
                print(f"\nSolution {i+1}:")
                sym_vars = found_state.globals.get('inputs', [])
                output_exprs = found_state.globals.get('output_constraints', [])

                if output_exprs:
                    print("Output variables:")
                    for name, expr in output_exprs:
                        try:
                            min_val = found_state.solver.min(expr)
                            max_val = found_state.solver.max(expr)
                            print(f"  {name}: Range [{min_val}, {max_val}]")
                            print(f"  Constraints on {name}: {expr}")
                        except Exception as e:
                            print(f"  {name}: (Could not solve for min/max: {e})")
                else:
                    print("No output constraints captured.")

                if sym_vars:
                    print("input variables:")
                    for sym_var_name, sym_var in sym_vars:
                        try:
                            min_val = found_state.solver.min(sym_var)
                            max_val = found_state.solver.max(sym_var)
                            print(f"  {sym_var_name}: Range [{min_val:#x}, {max_val:#x}]")
                            print(f"  Constraints on {sym_var_name}: {sym_var}")
                        except Exception as e:
                            print(f"  {sym_var_name}: (Could not solve for min/max: {e})")
                else:
                    print("No input variables captured.")

                constraints = str(found_state.solver.constraints)
                if len(constraints) > 250:
                    constraints = constraints[:250] + "..."
                print(f"All Constraints for Solution {i+1}: {constraints}")

                # ---------- new comparison block --------------------------------
                io_states: list[IOState] | None = found_state.globals.get('io_states', [])
                for ios in io_states:
                    ios.print_rich()
                    snapshot.add_output(ios)
    print("\n\n\n")
    snapshot.print_rich()
    print("\n\nDone!\n")

if __name__ == "__main__":
    main()