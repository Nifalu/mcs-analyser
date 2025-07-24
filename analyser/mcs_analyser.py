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
from analyser.output_checker import \
    setup_output_checker, \
    OutputChecker
from analyser.can_simulator import Component, Message, CANBus
from utils.logger import logger
log = logger(__name__)

NUM_FIND = 100

class MCSAnalyser:

    def __init__(self, component: Component):
        self.component: Component = component

        self.output_addrs = None
        self.output_checker = None

        self.current_input_combinations = None

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
            # Run in unconstrained mode to figure out how many inputs this component needs
            InputTracker.new(self.component.name)
            self._run_analysis(entry_points)
        else:
            self.current_input_combinations = self._generate_input_combinations(length=self.component.max_expected_inputs)
            for i, combination in enumerate(self.current_input_combinations):
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

            if self.output_addrs:
                log.debug(f"Finding all solutions from {entry_point_copy.addr:#x}")
                simgr.explore(
                    find=list(self.output_addrs.keys()),
                    cfg=self.cfg,
                    num_find=NUM_FIND,
                )
                log.debug(f"Found {len(simgr.found)} solutions")
            else:
                log.error(f"About to simulate. Expecting maximum of {InputTracker.max_inputs_counted} inputs")
                latest_state = None
                step_count = 0
                max_steps = 10000

                while simgr.active and step_count < max_steps:
                    latest_state = simgr.active[0]
                    simgr.step()
                    step_count += 1
                log.error(f"stepped {step_count} steps and read {InputTracker.input_counter} inputs, max_expected_inputs={InputTracker.max_inputs_counted}")

                OutputChecker.extract_subscriptions(self.component, latest_state)
                CANBus.write(None, InputTracker.get_consumed_messages(), self.component.name)

    def _capture_output(self, state: SimState):
            result: Message | None = self.output_checker.check(state, self.output_addrs.keys())
            if result is not None:
                self.component.update_max_expected_inputs(InputTracker.max_inputs_counted)
                if result.msg_type.is_symbolic():
                    log.warning(f"{self.component.name} produced a symbolic msg_id {result.msg_type}")
                else:
                    self.component.add_produced_msg_id(result.msg_type.bv.concrete_value)

                CANBus.write(result, InputTracker.get_consumed_messages()) # here we need to write

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

    def _generate_input_combinations(self, allow_repetition=False, length=None, warn_threshold=100):
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
        inputs = CANBus.read_all_msgs_of_types(self.component.subscriptions)

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
            log.debug(f"Yielding msg_id {c.msg_type}")
            yield c.msg_type      # Yield destination IOState
            log.debug(f"Yielding msg_data {c.msg_data}")
            yield c.msg_data  # Yield data IOState