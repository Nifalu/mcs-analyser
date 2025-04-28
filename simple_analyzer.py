from logger import logger
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
from rich import print

import \
    angr
from angr import \
    SimulationManager, \
    SimState

import re
import networkx as nx

BINARY = "./bin/findme_x86"
INTERESTING_INPUTS = ['scanf', 'gets', 'read']
INTERESTING_OUTPUTS = ['printf', 'puts', 'write']


class SimpleAnalyzer:

    """
    Have some hooks to track the IO operations.
    """
    class InputHook(angr.SimProcedure):
        def run(self, fmt, ptr):

            sym_var_count = self.state.globals.get('scanf_count', 0)
            sym_var_name = f'scanf_{sym_var_count}'
            sym_var = self.state.solver.BVS(sym_var_name, 32)
            # store the value in the memory location pointed to by ptr
            self.state.memory.store(ptr, sym_var, endness=self.state.arch.memory_endness)

            if 'sym_vars' not in self.state.globals:
                self.state.globals['sym_vars'] = []
            self.state.globals['sym_vars'].append((sym_var_name, sym_var))

            self.state.globals['scanf_count'] = sym_var_count + 1

            return 1


    def __init__(self, binary: str) -> None:
        """
        Initialize the SimpleAnalyzer with the binary to analyze.
        :param binary: Path to the binary file.
        """
        self.binary = binary
        self.proj = angr.Project(self.binary, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGEmulated()
        self.logger = logger("SimpleAnalyzer", level=DEBUG)


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
            functions=list[int]) -> None:
        """
        Hook interesting functions in the binary
        :param functions:
        :return: set of input and output function addresses
        """
        for addr in functions:
            self.proj.hook(addr, SimpleAnalyzer.InputHook()) if not self.proj.is_hooked(addr) else None



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
            self.logger.warning("Found a lot of input functions...")
        if len(output_funcs) > 5:
            self.logger.warning("Found a lot of output functions...")

        return input_funcs, output_funcs


    def _find_function_addresses(self, pattern: re.Pattern) -> set[int]:
        """
        Pass a list of function names to find in the binary.
        :param pattern:
        :return: Set of function addresses
        """
        found_funcs = set()

        self.logger.info(f"Searching for functions matching pattern: {pattern.pattern}")

        for func in self.cfg.kb.functions.values():
            if func.name and pattern.search(func.name):
                self.logger.info(f"{func.name.ljust(15)} at {func.addr:#x}")
                found_funcs.add(func.addr)

        if not found_funcs:
            self.logger.warning(f"No function addresses found matching pattern {pattern.pattern}")
        return found_funcs

    def capture_call_states(self, func_addr: int) -> list[angr.SimState]:
        """
        :param func_addr:
        :return: list of SimState objects
        """
        initial_state: SimState = self.proj.factory.entry_state()
        simgr: SimulationManager = self.proj.factory.simgr(initial_state)

        self.logger.info(f"Capturing call states for function at {func_addr:#x}")
        self.logger.info(f"Exploring from {initial_state.addr:#x} to {func_addr:#x}")

        simgr.explore(find=func_addr, cfg=self.cfg)

        if not simgr.found:
            self.logger.warning(f"Could not reach function addr at {func_addr:#x}")
        else:
            self.logger.info(f"Found {len(simgr.found)} states that call {func_addr:#x}")
        return simgr.found


    def find_all_solutions(self, entry_state: SimState, targets: list[int], max_solutions: int = 5) -> set[SimState]:
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

        self.logger.info(f"Finding all solutions from {entry_state.addr:#x}")

        simgr.explore(
            find=targets,
            cfg=self.cfg,
            num_find=max_solutions,
        )

        self.logger.info(f"Found {len(simgr.found)} solutions")

        if len(simgr.found) == max_solutions:
            self.logger.warning(f"Found {max_solutions} solutions, consider increasing the max_solutions parameter.")

        solutions = set()

        for i, found_state in enumerate(simgr.found):
            if 'sym_vars' in found_state.globals and found_state.globals['sym_vars']:
                solutions.add(found_state)

        return solutions


    def backtrack(self, out_addrs: set[int], in_addrs: set[int]) -> dict[int, dict[str, set[int]]]:
        """
        :param out_addrs: set of output function addresses
        :param in_addrs: set of input function addresses
        :return: a dict of (input, output) function addresses and the whitelist of addresses
        """
        reversed_graph = self.cfg.graph.reverse()

        # our addr should point to scanf or similar which are calls so should be at the beginning of a block.
        # so we can use force_fastpath=True. We are interested in user functions and not sys_calls.
        proj_entry = self.cfg.model.get_any_node(self.proj.entry, is_syscall=False, force_fastpath=True)
        in_nodes = {self.cfg.model.get_any_node(addr, is_syscall=False, force_fastpath=True) for addr in in_addrs}
        out_nodes = {self.cfg.model.get_any_node(addr, is_syscall=False, force_fastpath=True) for addr in out_addrs}

        result = {} # input_addr -> {whitelist: set, outputs: set}
        self.logger.info(f"Backtracking from {len(out_nodes)} output functions to {len(in_nodes)} input functions")
        for in_node in in_nodes:
            # If we cannot reach the input function from the entry point, we discard it.
            if not nx.has_path(self.cfg.graph, source=proj_entry, target=in_node):
                self.logger.info(f"Input function at {in_node.addr:#x} is unreachable from entry point.")
                continue

            local_whitelist = set()
            reachable_outputs = set()

            for out_node in out_nodes:

                if not nx.has_path(reversed_graph, source=out_node, target=in_node):
                    self.logger.info(f"Output function at {out_node.addr:#x} is unreachable from input function at {in_node.addr:#x}")

                # A simple path is a path with no repeated nodes,
                # so we should not have loops and technically not need a cutoff...?
                reachable_outputs.add(out_node.addr)
                for path in nx.all_simple_paths(reversed_graph, source=out_node, target=in_node):
                    local_whitelist.update((node.addr for node in path))

            result[in_node.addr] = {
                "whitelist": local_whitelist,
                "outputs": reachable_outputs
            }

        self.logger.info("Backtracked whitelists for inputs:")
        for input_addr, path_info in result.items():
            outputs = ", ".join(f"{addr:#x}" for addr in path_info["outputs"])
            whitelist = ", ".join(f"{addr:#x}" for addr in path_info["whitelist"])

            self.logger.info(f"Input function at {input_addr:#x} can reach output functions at [{outputs}]")
            self.logger.info(f"Whitelist of addresses: [{whitelist}]")

        return result



def main():

    sa = SimpleAnalyzer(BINARY)
    in_addrs, out_addrs = sa.find_interesting_functions()
    sa.hook_interesting_functions(in_addrs)

    for addr in in_addrs:
        call_states = sa.capture_call_states(addr)
        for state in call_states:
            solutions = sa.find_all_solutions(state, out_addrs, max_solutions=5)
            for i, found_state in enumerate(solutions):

                print(f"\nSolution {i+1}:")
                sym_vars = found_state.globals.get('sym_vars', [])

                for sym_var_name, sym_var in sym_vars:
                    min_val = found_state.solver.min(sym_var)
                    max_val = found_state.solver.max(sym_var)
                    print(f"Min value for {sym_var_name}: {min_val}")
                    print(f"Max value for {sym_var_name}: {max_val}")

                constraints = str(found_state.solver.constraints)
                if len(constraints) > 250:
                    constraints = constraints[:250] + "..."
                print(f"Constraints for Solution {i+1}: {constraints}")


    print("\n\nDone!\n")

if __name__ == "__main__":
    main()