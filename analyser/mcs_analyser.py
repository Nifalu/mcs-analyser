import itertools
import re
import angr
import claripy.ast.bv as bv_module
from math import factorial
from angr import SimState, SimulationManager


from analyser.config import Config
from analyser.input_hooks import InputHookRegistry
from analyser.input_tracker import \
    InputTracker
from analyser.output_checker import setup_output_checker
from analyser.can_simulator import Component, Message, CANBus
from analyser.io_state import IOState
from utils.logger import logger
log = logger(__name__)

NUM_FIND = 100

class MCSAnalyser:

    def __init__(self, component: Component):
        self.component: Component = component

        self.output_addrs = None
        self.output_checker = None

        self.produced_msg_ids: set[IOState] = set()
        self.consumed_sources: set[int] = set()

        self.input_hook_registry: InputHookRegistry = InputHookRegistry()
        self.proj = angr.Project(self.component.path, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGEmulated()

    def analyse(self) -> None:
        log.info(f"\n=========== Going to Analyse {self.component} ============")
        input_addrs = self._find_addr(Config.input_hooks)
        log.info(f"Input Functions {[(name, hex(addr)) for addr, name in input_addrs.items()]}")
        entry_points = self._get_sim_states(input_addrs.keys())
        self.output_addrs = self._find_addr(Config.output_hooks)
        log.info(f"Output Functions {[(name, hex(addr)) for addr, name in self.output_addrs.items()]}")
        self.output_checker = setup_output_checker(self.component, self.output_addrs)

        for addr, func_name in input_addrs.items():
            if not self.proj.is_hooked(addr):
                hook = self.input_hook_registry.create_hook(func_name)
                self.proj.hook(addr, hook)
                log.debug(f"Hooked {func_name} at {hex(addr)} with {hook.__class__.__name__}")

        if self.component.max_expected_inputs == 0:
            InputTracker.new(self.component.name)
            self._run_analysis(entry_points)
        else:
            input_combinations = self._generate_input_combinations(length=self.component.max_expected_inputs)
            for i, combination in enumerate(input_combinations):
                InputTracker.new(self.component.name, combination)
                self._run_analysis(entry_points)

    def _run_analysis(self, entry_points: list[SimState]) -> None:
        for entry_point in entry_points:

            InputTracker.soft_reset()
            bv_module.var_counter = itertools.count()

            entry_point_copy = entry_point.copy()
            entry_point_copy.inspect.b(
                'call',
                when=angr.BP_BEFORE,
                action=lambda state: self._capture_output(state)
            )
            simgr: SimulationManager = self.proj.factory.simgr(entry_point_copy)

            log.debug(f"Finding all solutions from {entry_point_copy.addr:#x}")

            simgr.explore(
                find=list(self.output_addrs.keys()),
                cfg=self.cfg,
                num_find=NUM_FIND,
            )

            log.debug(f"Found {len(simgr.found)} solutions")

    def _capture_output(self, state: SimState):
            result: Message | None = self.output_checker.check(state, self.output_addrs.keys())
            if result is not None:
                self.component.update_max_expected_inputs(InputTracker.max_inputs_counted)
                self.consumed_sources.union(InputTracker.get_consumed_sources())
                self.produced_msg_ids.add(result.msg_id)
            return result

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
                    normalized_name = InputHookRegistry.normalize_function_name(func.name)
                    found[func.addr] = normalized_name
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
    def _generate_input_combinations(allow_repetition=False, length=None, warn_threshold=100):
        """
        Lazily generates all possible permutations of the inputs.

        Args:
            allow_repetition: Whether to allow selecting the same input multiple times (default: False)
            length: Length of permutations to generate (default: len(inputs))
            warn_threshold: Number of combinations above which to log.debug a warning

        Yields:
            Lists representing permutations of the inputs

        Raises:
            ValueError: If length > len(inputs) and allow_repetition=False
        """
        log.debug("Generating permutations with:")
        inputs = CANBus.read_all()
        for msg in inputs:
            log.debug(f"  {msg}")

        n = len(inputs)
        k = length//2 if length is not None else n

        # Validate
        if not allow_repetition and k > n:
            raise ValueError(f"Cannot generate permutations of length {k} from {n} inputs without repetition.")

        # Calculate total combinations
        if allow_repetition:
            total_combinations = n ** k
        else:
            total_combinations = factorial(n) // factorial(n - k)

        log.info(f"Generated {total_combinations} input combinations of length {length} to analyze")

        if total_combinations > warn_threshold:
            log.warning(f"Large number of input combinations to check: {total_combinations:,} combinations!")

        # Generate permutations
        if allow_repetition:
            # Use product for permutations with repetition
            yield from itertools.product(inputs, repeat=k)
        else:
            # Use permutations for permutations without repetition
            yield from itertools.permutations(inputs, k)


    @staticmethod
    def _flatten_combinations(combination: tuple[Message, ...] | tuple[Message, Message]):
        for c in combination:
            log.debug(f"Yielding msg_id {c.msg_id}")
            yield c.msg_id      # Yield destination IOState
            log.debug(f"Yielding msg_data {c.msg_data}")
            yield c.msg_data  # Yield data IOState

    @staticmethod
    def extract_symbols(binary_path, prefix="subscriptions", extract_array=True) -> list[int] | dict[int, str]:
        """
        Extract symbols from a compiled binary.

        Args:
            binary_path: Path to the binary file
            prefix: Symbol prefix to search for (e.g., "subscriptions", "MSG_")
            extract_array: If True, treat symbol as array and extract all elements.
                          If False, just extract single value.

        Returns:
            - If extract_array=True: List of values from the array
            - If extract_array=False: Dict of {symbol_name: value}
        """
        try:
            proj = angr.Project(binary_path, auto_load_libs=False)
        except Exception as e:
            log.error(f"Error loading binary: {e} during symbol extraction")
            return None if extract_array else {}

        log.debug(f"Loaded binary: {binary_path}")

        results = [] if extract_array else {}

        for symbol in proj.loader.main_object.symbols:
            if not symbol.name:
                continue

            # Check if symbol starts with prefix (with or without underscore)
            clean_name = symbol.name.lstrip('_')
            if clean_name.startswith(prefix):
                log.debug(f"Found symbol: {symbol.name} at 0x{symbol.rebased_addr:x}, size: {symbol.size}")

                if hasattr(symbol, 'size') and symbol.size > 0:
                    if extract_array:
                        # Extract array elements
                        num_elements = symbol.size // 8
                        values = []
                        for i in range(num_elements):
                            addr = symbol.rebased_addr + (i * 8)
                            value = proj.loader.memory.unpack_word(addr, size=8)
                            values.append(value)

                        return values  # Return first matching array
                    else:
                        # Extract single value
                        value = proj.loader.memory.unpack_word(symbol.rebased_addr, size=8)
                        if results[value]:
                            raise(ValueError(f"Multiple Message ID's with the same name detected: {value}"))
                        results[value] = clean_name

        if extract_array:
            log.warning(f"No symbols starting with '{prefix}' found in binary")
            return None
        else:
            return results