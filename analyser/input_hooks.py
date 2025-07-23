import re
import angr
from abc import \
    abstractmethod, \
    ABC

from analyser.input_tracker import InputTracker
from utils.logger import logger
log = logger(__name__)

class InputHookBase(angr.SimProcedure, ABC):
    """Base class for input function hooks"""

    def __init__(self):
        super().__init__()

    @abstractmethod
    def run(self, *args, **kwargs):
        """Must be implemented by subclasses with correct signature"""
        pass

    @classmethod
    @abstractmethod
    def can_handle(cls) -> list[str]:
        """Returns a list of function names this hook can handle"""
        pass


class ScanfHook(InputHookBase):
    """Hook for scanf-family functions"""

    @classmethod
    def can_handle(cls) -> list[str]:
        return ['scanf']

    def run(self, fmt_str_ptr):

        log.debug("Input hook triggered")
        # Figure out how many format string arguments we got
        fmt_str = self.state.solver.eval(
            self.state.memory.load(fmt_str_ptr, 1024),
            cast_to=bytes,
        )
        fmt_str = fmt_str.split(b'\x00')[0].decode('utf-8', errors='ignore')
        fmt_str = fmt_str.replace('%%', '')
        num_args = len(re.findall(r'%', fmt_str))
        num_args += fmt_str.count('*')

        log.debug(f"Calculated {num_args} arguments from {fmt_str}")

        if num_args > 2:
            log.warning(f"scanf() with more than two arguments detected: {fmt_str}")

        if self.state.arch.name != 'AMD64':
            raise NotImplementedError(f"scanf() is not implemented for {self.state.arch.name} architecture")

        arg_regs = ['rsi', 'rdx', 'rcx', 'r8', 'r9']
        for i in range(min(num_args, len(arg_regs))):
            ptr = getattr(self.state.regs, arg_regs[i])
            next_input = InputTracker.get_next_input()
            if next_input.constraints:
                self.state.solver.add(*next_input.constraints)
                self.state.memory.store(ptr, next_input.bv, endness=self.state.arch.memory_endness)

        return

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

    def create_hook(self, func_name: str):
        """Create a hook instance for the given function"""
        hook_class = self.get_hook_class(func_name)
        if hook_class:
            return hook_class()
        else:
            log.error(f"Could not create hook for '{func_name}'")
            raise Exception(f"Could not find a hook for '{func_name}'")