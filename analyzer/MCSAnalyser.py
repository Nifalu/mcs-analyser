import itertools
import re
import angr
from math import factorial
from pathlib import Path
from angr import SimState, SimulationManager

from analyzer.OutputChecker import \
    setup_output_checker
from analyzer.coordinator import CANNode, CANMessage, CANBus
from analyzer.io_state import IOState
from utils.logger import logger
log = logger(__name__)

class InputHook(angr.SimProcedure):
    def __init__(self, input_generator):
        super().__init__()
        self.input_generator = input_generator

    def run(self, ptr):
        next_input: IOState = self.input_generator()
        if next_input.constraints:
            self.state.solver.add(*next_input.constraints)

        self.state.memory.store(ptr, next_input.bv, endness=self.state.arch.memory_endness)

        if 'inputs' not in self.state.globals:
            self.state.globals['inputs'] = []
        self.state.globals['inputs'].append((next_input.name, next_input.bv))

        return 1

class MCSAnalyser:

    def __init__(self, node: CANNode):
        self.node: CANNode = node
        self.proj = angr.Project(self.node.path, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGEmulated()
        self.current_input_iterator = None
        self.current_input_list = None
        self.output_addrs = None
        self.output_checker = None
        self.results: list[CANMessage] = []

    def analyse(self):

        input_combinations = self._generate_input_combinations(self.node.read_all())
        input_addrs = self._find_addr(self.node.config().input_hooks)
        entry_points = self._get_sim_states(input_addrs.values())
        self.output_addrs = self._find_addr(self.node.config().output_hooks)
        self.output_checker = setup_output_checker(str(self.node.path), self.output_addrs)

        """Hook all our input addresses"""
        for addr in input_addrs.values():
            self.proj.hook(addr, InputHook(self.yield_input)) if not self.proj.is_hooked(addr) else None

        for combination in input_combinations:
            self.current_input_list = list(self._flatten_combinations(combination))

            for entry_point in entry_points:
                self.current_input_iterator = iter(self.current_input_list)
                self._run_analysis(entry_point.copy())



    def _run_analysis(self, entry_point: SimState) -> None:

        entry_point.inspect.b(
            'call',
            when=angr.BP_BEFORE,
            action=lambda state: self.output_checker.check_output(state, self.output_addrs.values(), self.store_result_callback)
        )
        self._get_sim_states(self.output_addrs.values(), entry_point)


    def store_result_callback(self, can_msg: CANMessage):
        print(can_msg)
        self.results.append(can_msg)

    def yield_input(self):
        """
        A Hook for the Hook to retrieve the next input.
        :return:
        """
        try:
            return next(self.current_input_iterator)
        except StopIteration:
            log.error("Requested more inputs than available... => Creating unconstrained input")
            return IOState.unconstrained(f"{self.node.path}_unconstrained", self.node.config().default_var_length)

    def _find_addr(self, names: list[str]):
        """
        Find addresses of functions matching the given names.
        :param names:
        :return:
        """
        escaped_names = [re.escape(name) for name in names]
        pattern = re.compile("|".join(escaped_names))

        log.debug(f"Finding addresses of functions matching pattern {pattern}")
        found = {}

        for func in self.cfg.kb.functions.values():
            if func.name and pattern.search(func.name):
                section = self.proj.loader.find_section_containing(func.addr)
                if section and section.is_executable:
                    log.debug(f"Found {func.name} at {hex(func.addr)}")
                    found[func.name] = func.addr
                else:
                    log.debug(f"Ignoring {func.name} at {hex(func.addr)} as it is not executable. Probably a GOT entry")
        if not found:
            log.warning(f"No addresses found for {pattern}")
        return found

    def _get_sim_states(self, addrs, entry_point: SimState=None) -> list[SimState]:
        """
        Explore the CFG and retrieve the SimStates of the given addresses
        :param addrs:
        :return:
        """
        NUM_FIND = 10_000

        initial_state: SimState = self.proj.factory.entry_state() if entry_point is None else entry_point
        simgr: SimulationManager = self.proj.factory.simgr(initial_state)

        log.debug(f"Getting SimStates for {[hex(x) for x in addrs]}")

        simgr.explore(find=list(addrs), num_find=NUM_FIND, cfg=self.cfg)
        if not simgr.found:
            log.error("Could not reach any addresses")
            return list()
        else:
            n = len(simgr.found)
            if n == NUM_FIND:
                log.warning(f"Hit the maximum number of solutions ({n}), consider increasing the 'NUM_FIND' parameter.")
            log.debug(f"Found {len(simgr.found)} SimStates for {[hex(x) for x in addrs]}")
            return simgr.found

    @staticmethod
    def _generate_input_combinations(inputs: list[CANMessage], allow_repetition=False, length=None, warn_threshold=10000):
        """
        Lazily generates all possible permutations of the inputs.

        Args:
            inputs: List of available inputs
            allow_repetition: Whether to allow selecting the same input multiple times (default: False)
            length: Length of permutations to generate (default: len(inputs))
            warn_threshold: Number of combinations above which to print a warning

        Yields:
            Lists representing permutations of the inputs

        Raises:
            ValueError: If length > len(inputs) and allow_repetition=False
        """
        n = len(inputs)
        k = length if length is not None else n

        # Validate
        if not allow_repetition and k > n:
            raise ValueError(f"Cannot generate permutations of length {k} from {n} inputs without repetition.")

        # Calculate total combinations
        if allow_repetition:
            total_combinations = n ** k
        else:
            total_combinations = factorial(n) // factorial(n - k)

        if total_combinations > warn_threshold:
            print(f"Warning: This will generate {total_combinations:,} combinations!")

        # Generate permutations
        if allow_repetition:
            # Use product for permutations with repetition
            yield from itertools.product(inputs, repeat=k)
        else:
            # Use permutations for permutations without repetition
            yield from itertools.permutations(inputs, k)


    @staticmethod
    def _flatten_combinations(combination: tuple[CANMessage, ...] | tuple[CANMessage, CANMessage]):
        for c in combination:
            yield [c.dest, c.msg_data]


def mainA():
    bus = CANBus(Path.cwd() / "config.json")
    print(bus)
    for node in bus.nodes:
        MCSAnalyser(node).analyse()