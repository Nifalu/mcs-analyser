from utils.logger import logger
from rich import print
from pathlib import Path
from analyzer.io_state import \
    IOState, \
    IOSnapshot, \
    IOConfig

import \
    angr
from angr import \
    SimulationManager, \
    SimState

import re

from schnauzer import VisualizationClient

BINARY = "./bin/test_x86"

INTERESTING_INPUTS = ['scanf', 'gets', 'read']
INTERESTING_OUTPUTS = ['printf', 'puts', 'write']

log = logger("SimpleAnalyzer")


class SimpleAnalyzer:

    """
    Have some hooks to track the IO operations.
    """

    class InputHook(angr.SimProcedure):
        def __init__(self, inputs: list[IOState]) -> None:
            super().__init__()
            self.inputs: list[IOState] = inputs


        def run(self, fmt, ptr):
            input_count = self.state.globals.get('input_count', 0)

            if input_count < len(self.inputs):
                ios = self.inputs[input_count]
                bv = ios.bv
                bv_name = ios.name
                if ios.constraints:
                    self.state.solver.add(*ios.constraints)
            else:
                log.warning(f"Input count ({input_count}) exceeds number of passed inputs ({len(self.inputs)}). Using default input.")
                bv_name = f"auto_input_{input_count}"
                bv = self.state.solver.BVS(bv_name, 64)
                self.inputs.append(IOState(bv_name, bv, []))


            # store the value in the memory location pointed to by ptr
            self.state.memory.store(ptr, bv, endness=self.state.arch.memory_endness)

            if 'inputs' not in self.state.globals:
                self.state.globals['inputs'] = []
            self.state.globals['inputs'].append((bv_name, bv))

            self.state.globals['input_count'] = input_count + 1

            return 1

    def __init__(self, binary: str | Path, inputs: list[IOState], config: IOConfig) -> None:
        """
        Initialize the SimpleAnalyzer with the binary to analyze.
        :param binary: Path to the binary file.
        """
        self.binary = binary
        self.inputs = inputs
        self.config = config
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

        log.debug(f"Searching for functions matching pattern: {pattern.pattern}")

        for func in self.cfg.kb.functions.values():
            if func.name and pattern.search(func.name):
                log.debug(f"{func.name.ljust(15)} at {func.addr:#x}")
                found_funcs.add(func.addr)

        if not found_funcs:
            log.warning(f"No function addresses found matching pattern {pattern.pattern}")
        return found_funcs

    def capture_call_states(self, func_addrs: list[int], num_find: int = 10) -> [angr.SimState]:
        """
        Capture the call states for a specific function address.
        Note: Does N * explore() !!

        Maybe we can optimize here to not call explore() in a loop...

        :param num_find:
        :param func_addrs:
        :return: list of SimState objects
        """
        initial_state: SimState = self.proj.factory.entry_state()
        simgr: SimulationManager = self.proj.factory.simgr(initial_state)

        log.debug(f"Capturing call states")

        call_states = []
        for addr in func_addrs:
            log.debug(f"Exploring from {initial_state.addr:#x} to {addr:#x}")
            simgr.explore(find=addr, num_find=num_find, cfg=self.cfg)
            if not simgr.found:
                log.warning(f"Could not reach function addr at {addr:#x}")
            else:
                log.debug(f"Found {len(simgr.found)} states that call {addr:#x}")
                call_states.extend(simgr.found)

        return simgr.found

    def find_all_solutions(self, entry_state: SimState, targets: list[int], max_solutions: int = 5) -> set[SimState]:
        """
        Find all solutions to the binary that lead to a specific output.
        Note: Does explore() !!

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

        log.debug(f"Finding all solutions from {entry_state.addr:#x}")

        simgr.explore(
            find=targets,
            cfg=self.cfg,
            num_find=max_solutions,
        )

        log.debug(f"Found {len(simgr.found)} solutions")

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

        call_target = state.inspect.function_address
        concrete_call_target = state.solver.eval(call_target, cast_to=int)
        log.debug(f"Checking if {concrete_call_target} is in {output_func_addrs}")

        if concrete_call_target not in output_func_addrs:
            log.debug(f"It is not. Skipping...")
            return

        log.debug(f"Output function called at {concrete_call_target:#x}")

        # Get format string to determine number of arguments
        format_str_ptr = self._get_format_string_ptr(state)
        try:
            format_str = state.solver.eval(state.memory.load(format_str_ptr, 1024), cast_to=bytes)
            format_str = format_str.split(b'\x00')[0].decode('utf-8', errors='ignore')
            num_args = self._count_format_specifiers(format_str)
            log.debug(f"Format string: '{format_str}', expecting {num_args} arguments")
        except:
            # If we can't parse format string, assume a reasonable default
            num_args = 2  # or make this configurable
            log.warning("Could not parse format string, assuming 2 arguments")

        # Get all arguments
        args = self._get_printf_args(state, num_args)

        # Initialize globals if needed
        if 'output_constraints' not in state.globals:
            state.globals['output_constraints'] = []
        if 'io_states' not in state.globals:
            state.globals['io_states'] = []

        # Process each argument
        for i, output_value in enumerate(args):
            if state.solver.symbolic(output_value):
                log.info(f"Output argument {i} is symbolic! Expr: {output_value}")
            else:
                concrete_val = state.solver.eval(output_value, cast_to=int)
                log.info(f"Output argument {i} is concrete: {concrete_val}")

            # Store constraint with index
            constraint_name = f'output_{concrete_call_target:x}_arg{i}'
            state.globals['output_constraints'].append((constraint_name, output_value))

            # Create IOState for each argument
            try:
                ios = IOState.from_state(
                    f"{self.binary}_out_{concrete_call_target:x}_arg{i}",
                    output_value,
                    state
                )
                state.globals['io_states'].append(ios)
                log.info(f"Captured IOState for arg {i}: {ios}")
            except ValueError as e:
                log.exception(f"Error creating IOState for arg {i}:", e)

    def _get_format_string_ptr(self, state):
        """Get the format string pointer based on architecture"""
        arch_name = state.arch.name.lower()
        if 'x86' in arch_name and '64' not in arch_name:
            return state.memory.load(state.regs.esp + 4, 4)
        elif 'amd64' in arch_name or 'x86_64' in arch_name:
            return state.regs.rdi
        else:
            raise NotImplementedError(f"Architecture {arch_name} not supported")

    def _count_format_specifiers(self, format_str):
        """Count format specifiers in a format string"""
        import re
        # Match format specifiers like %d, %u, %x, %s, etc.
        # Ignore escaped %%
        format_str = format_str.replace('%%', '')
        specifiers = re.findall(r'%[diouxXeEfFgGaAcspn]', format_str)
        return len(specifiers)

    def _get_printf_args(self, state, num_args):
        """Get printf arguments based on calling convention"""
        arch_name = state.arch.name.lower()
        args = []

        if 'x86' in arch_name and '64' not in arch_name:
            # x86 32-bit: all args on stack after format string
            for i in range(num_args):
                arg_addr = state.regs.esp + 8 + (i * 4)  # esp+4 is format string
                args.append(state.memory.load(arg_addr, 4))

        elif 'amd64' in arch_name or 'x86_64' in arch_name:
            # x86_64: first 6 args in registers (rdi has format string)
            reg_args = ['rsi', 'rdx', 'rcx', 'r8', 'r9']

            for i in range(num_args):
                if i < len(reg_args):
                    args.append(getattr(state.regs, reg_args[i]))
                else:
                    # Additional arguments on stack
                    stack_offset = (i - len(reg_args)) * 8
                    args.append(state.memory.load(state.regs.rsp + stack_offset, 8))

        else:
            log.warning(f"Architecture {arch_name} not handled")
            return []

        return args


    def analyze(self) -> IOSnapshot:
        in_addrs, out_addrs = self.find_interesting_functions()
        entry_states = self.capture_call_states(in_addrs, num_find=10)
        self.hook_interesting_functions(in_addrs)
        snapshot = IOSnapshot(f"Binary {self.binary}")

        all_solutions: list[SimState] = []
        for state in entry_states:
            all_solutions.extend(self.find_all_solutions(state, out_addrs, max_solutions=10))

        for solution in all_solutions:
            io_states: list[IOState] = solution.globals.get('io_states', [])

            if len(io_states) < 2:
                log.error("A valid solution must always output a 'targetId' and a 'msg'... skipping!")
                continue
            if io_states[0].is_symbolic():
                log.error("The target ID must be concrete, skipping this solution!")
                continue

            target = io_states[0].bv.concrete_value
            for ios in io_states[1:]:
                snapshot.add_output(target, ios)

        return snapshot





def main():

    # Have an unconstrained input (IOState)
    initial_input = IOState.unconstrained("input", 64)

    sa = SimpleAnalyzer(BINARY, [initial_input])

    vc = VisualizationClient()
    vc.send_graph(sa.cfg.graph, sa.binary)

    """
    # Find interesting functions in the binary (i.E scanf, printf, etc.)
    in_addrs, out_addrs = sa.find_interesting_functions()
    # Capture the call states of those to correctly set up the entry states
    entry_states = sa.capture_call_states(in_addrs, num_find=10)
    # Hook the interesting functions in the binary
    sa.hook_interesting_functions(in_addrs)

    # Prepare a snapshot to store the results of this analysis
    snapshot = IOSnapshot(f"Binary {sa.binary}")
    snapshot.add_input(sa.inputs)

    # Iterate over the entry states and find all solutions for each
    all_solutions = []
    for state in entry_states:
        all_solutions.extend(sa.find_all_solutions(state, out_addrs, max_solutions=10))

    print_solutions(all_solutions, snapshot)
    """

def print_solutions(all_solutions: list[SimState], snapshot: IOSnapshot) -> None:
    for i, found_state in enumerate(all_solutions):
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