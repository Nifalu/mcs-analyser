import angr
from abc import abstractmethod
from analyzer.io_state import IOState
from utils.logger import logger
log = logger(__name__)

class InputHookBase(angr.SimProcedure):
    """Base class for input function hooks"""

    def __init__(self, input_generator):
        super().__init__()
        self.input_generator = input_generator

    @abstractmethod
    def run(self, *args, **kwargs):
        """Must be implemented by subclasses with correct signature"""
        pass

    @classmethod
    @abstractmethod
    def can_handle(cls) -> list[str]:
        """Returns a list of function names this hook can handle"""
        pass

    def get_next_input(self) -> IOState:
        """Common method to get next input and handle constraints"""
        next_input = self.input_generator()

        if next_input.constraints:
            self.state.solver.add(*next_input.constraints)
        return next_input

    def store_input_record(self, name: str, bv):
        """Common method to record inputs"""
        if 'inputs' not in self.state.globals:
            self.state.globals['inputs'] = []
        self.state.globals['inputs'].append((name, bv))


class ScanfHook(InputHookBase):
    """Hook for scanf-family functions"""

    @classmethod
    def can_handle(cls) -> list[str]:
        return ['scanf']

    def run(self, fmt, ptr):
        next_input = self.get_next_input()

        # Store at the pointer location
        self.state.memory.store(ptr, next_input.bv, endness=self.state.arch.memory_endness)
        self.store_input_record(next_input.name, next_input.bv)

        return 1  # scanf returns number of items read


class InputHookRegistry:
    """Registry to manage input function hooks"""
    prefixes = ['__isoc99_', '__isoc23_', '__', '_']
    suffixes = ['_chk', '@plt', '_s']

    def __init__(self):
        self.hook_map = {}
        self._register_default_hooks()

        # Common prefixes/suffixes to strip


    def _register_default_hooks(self):
        default_hooks = [
            ScanfHook
        ]
        for hook_class in default_hooks:
            self.register_hook(hook_class)

    @classmethod
    def register_prefix(cls, prefix: str):
        cls.prefixes.append(prefix)

    @classmethod
    def register_suffix(cls, suffix: str):
        cls.suffixes.append(suffix)

    def register_hook(self, hook_class):
        if not issubclass(hook_class, InputHookBase):
            raise ValueError(f"{hook_class} must be a subclass of InputHookBase")

        handled_functions = hook_class.can_handle()

        for func_name in handled_functions:
            if func_name in self.hook_map:
                log.debug(f"Overwriting hook for '{func_name}': {self.hook_map[func_name].__name__} -> {hook_class.__name__}")
            else:
                log.debug(f"Registering hook for '{func_name}': {hook_class.__name__}")
            self.hook_map[func_name] = hook_class

    @classmethod
    def normalize_function_name(cls, func_name: str) -> str:
        """Strip common prefixes/suffixes to get base function name"""
        if not func_name:
            return func_name

        normalized = func_name

        # Strip prefixes
        for prefix in cls.prefixes:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break

        # Strip suffixes
        for suffix in cls.suffixes:
            if normalized.endswith(suffix):
                normalized = normalized[:-len(suffix)]
                break

        return normalized

    def get_hook_class(self, func_name: str):
        """Get the appropriate hook class for a function"""
        # First try exact match
        hook_class = self.hook_map.get(func_name)
        if hook_class:
            return hook_class

        # Try normalized name
        normalized = self.normalize_function_name(func_name)
        hook_class = self.hook_map.get(normalized)
        if hook_class:
            return hook_class

        # Try partial matching
        for base_name, hook_class in self.hook_map.items():
            if base_name in func_name:
                log.debug(f"Partial match: '{func_name}' contains '{base_name}'")
                return hook_class

        return None

    def create_hook(self, func_name: str, input_generator):
        """Create a hook instance for the given function"""
        hook_class = self.get_hook_class(func_name)
        if hook_class:
            return hook_class(input_generator)
        else:
            log.error(f"Could not create hook for '{func_name}'")
            raise Exception(f"Could not find a hook for '{func_name}'")