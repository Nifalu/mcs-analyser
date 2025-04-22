import \
    angr
from angr import \
    SimulationManager, \
    SimState

import re

BINARY = "./bin/findme_x86"
INTERESTING_INPUTS = ['scanf', 'gets', 'read']
INTERESTING_OUTPUTS = ['printf', 'puts', 'write']

class SimpleAnalyzer:

    """
    Have some hooks to track the IO operations.
    """
    class InputHook(angr.SimProcedure):
        def run(self, fmt, ptr):
            # Simulate a scanf reading by using a symbolic variable
            x = self.state.solver.BVS('x', 32)
            # store the value in the memory location pointed to by ptr
            self.state.memory.store(ptr, x, endness=self.state.arch.memory_endness)
            # save the variable in state.globals for easy access
            self.state.globals['x'] = x
            return 1

    class OutputHook(angr.SimProcedure):
        def run(self, fmt, *args):
            self.state.globals['hit'] = True # Set a flag to indicate we hit an output function
            return 1


    def __init__(self, binary: str) -> None:
        """
        Initialize the SimpleAnalyzer with the binary to analyze.
        :param binary: Path to the binary file.
        """
        self.binary = binary
        self.proj = angr.Project(self.binary, auto_load_libs=False)


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
            print("Found a lot of input functions...")
        if len(output_funcs) > 5:
            print("Found a lot of output functions...")

        # Hook those addresses
        for addr in input_funcs:
            self.proj.hook(addr, SimpleAnalyzer.InputHook()) if not self.proj.is_hooked(addr) else None
        for addr in output_funcs:
            self.proj.hook(addr, SimpleAnalyzer.OutputHook()) if not self.proj.is_hooked(addr) else None

        return input_funcs, output_funcs


    def _find_function_addresses(self, pattern: re.Pattern) -> set[int]:
        """
        Pass a list of function names to find in the binary.
        :param pattern:
        :return: Set of function addresses
        """
        found_funcs = set()
        cfg = self.proj.analyses.CFGFast()

        print(f"\nSearching for functions matching pattern: {pattern.pattern}")

        for func in cfg.kb.functions.values():
            if func.name and pattern.search(func.name):
                print(f"{func.name.ljust(15)} at {func.addr:#x}")
                found_funcs.add(func.addr)

        if not found_funcs:
            raise RuntimeWarning(f"No function addresses found matching pattern {pattern}")
        return found_funcs


    def capture_call_states(self, func_addr: int) -> list[angr.SimState]:
        """
        Not sure if this makes sense as I travel there anyway??
        :param func_addr:
        :return: list of SimState objects
        """
        initial_state: SimState = self.proj.factory.entry_state()
        simgr: SimulationManager = self.proj.factory.simgr(initial_state)

        print(f"\nTrying to reach input state at addr {func_addr:#x}", end=" ")

        simgr.explore(find=func_addr)

        if not simgr.found:
            print(f"=> Could not reach function addr at {func_addr:#x}")
        else:
            print(f"=> Found {len(simgr.found)} states that call {func_addr:#x}")
        return simgr.found


    def find_all_solutions(self, entry_state: SimState, max_solutions: int = 5) -> None:
        """
        Find all solutions to the binary that lead to a specific output.
        :param max_solutions:
        :param entry_state: initial state of the binary
        :return: None
        """

        # Reset the hit flag to not include
        # interesting output functions that were
        # found on the way to the input state.
        entry_state.globals['hit'] = False
        simgr: SimulationManager = self.proj.factory.simgr(entry_state)

        print(f"Exploring from {entry_state.addr:#x}", end=" ")
        simgr.explore(
            find=lambda s: s.globals.get('hit', False),
            num_find=max_solutions,
        )
        print(f"=> Found {len(simgr.found)} solutions")
        if len(simgr.found) == max_solutions:
            print(f"Warning: Hit the max number of solutions ({max_solutions}), consider increasing it.")

        for i, found_state in enumerate(simgr.found):
            if 'x' in found_state.globals:
                input_value = found_state.globals['x']
                min_val = found_state.solver.min(input_value)
                max_val =found_state.solver.max(input_value)
                constraints = str(found_state.solver.constraints)
                # Avoid printing too long constraints
                if len(constraints) > 250:
                    constraints = constraints[:250] + "..."

                print(f"\nSolution {i+1}:")
                print(f"Found a path to Path A with input: {input_value}")
                print(f"Min value for x: {min_val}")
                print(f"Max value for x: {max_val}")
                print(f"Constraints for Path A: {constraints}")


def main():

    sa = SimpleAnalyzer(BINARY)
    in_addrs, out_addrs = sa.hook_interesting_functions()

    for addr in in_addrs:
        call_states = sa.capture_call_states(addr)
        for state in call_states:
            sa.find_all_solutions(state, max_solutions=5)

    print("\n\nDone!\n")

if __name__ == "__main__":
    main()