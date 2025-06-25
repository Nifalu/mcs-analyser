from abc import ABC, abstractmethod
import angr
import re
from typing import List, Optional
import logging

log = logging.getLogger(__name__)


class OutputFunctionParser(ABC):
    """Base class for parsing output function arguments"""

    @abstractmethod
    def can_handle(self, func_name: str, func_addr: int) -> bool:
        """Check if this parser can handle the given function"""
        pass

    @abstractmethod
    def parse_arguments(self, state: angr.SimState) -> List[any]:
        """Extract arguments from the function call"""
        pass


class PrintfParser(OutputFunctionParser):
    """Parser for printf-family functions"""

    def __init__(self):
        self.printf_functions = {
            'printf', 'fprintf', 'sprintf', 'snprintf',
            'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf'
        }

    def can_handle(self, func_name: str, func_addr: int) -> bool:
        return func_name in self.printf_functions

    def parse_arguments(self, state: angr.SimState) -> List[any]:
        format_str_ptr = self._get_format_string_ptr(state)
        try:
            format_str = state.solver.eval(state.memory.load(format_str_ptr, 1024), cast_to=bytes)
            format_str = format_str.split(b'\x00')[0].decode('utf-8', errors='ignore')
            num_args = self._count_format_specifiers(format_str)
            log.debug(f"Format string: '{format_str}', expecting {num_args} arguments")
        except:
            num_args = 2  # Default fallback
            log.warning("Could not parse format string, assuming 2 arguments")

        return self._get_printf_args(state, num_args)

    def _get_format_string_ptr(self, state):
        """Get the format string pointer based on architecture"""
        arch_name = state.arch.name.lower()
        if 'x86' in arch_name and '64' not in arch_name:
            log.warning("in x86 architecture")
            return state.memory.load(state.regs.esp + 4, 4)
        elif 'amd64' in arch_name or 'x86_64' in arch_name:
            return state.regs.rdi
        else:
            raise NotImplementedError(f"Architecture {arch_name} not supported")

    def _count_format_specifiers(self, format_str):
        """Count format specifiers in a format string"""
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
                arg_addr = state.regs.esp + 8 + (i * 4)
                args.append(state.memory.load(arg_addr, 4))

        elif 'amd64' in arch_name or 'x86_64' in arch_name:
            # x86_64: first 6 args in registers (rdi has format string)
            reg_args = ['rsi', 'rdx', 'rcx', 'r8', 'r9']

            for i in range(num_args):
                if i < len(reg_args):
                    args.append(getattr(state.regs, reg_args[i]))
                else:
                    stack_offset = (i - len(reg_args)) * 8
                    args.append(state.memory.load(state.regs.rsp + stack_offset, 8))
        else:
            log.warning(f"Architecture {arch_name} not handled")

        return args


class OutputParserRegistry:
    """Registry for output function parsers"""

    def __init__(self):
        self.parsers: list[OutputFunctionParser] = [
            PrintfParser(),
        ]
        self.address_to_name = {}  # Cache for address -> function name mapping

    def register_parser(self, parser: OutputFunctionParser):
        """Register a new parser"""
        self.parsers.append(parser)

    def register_function(self, addr: int, name: str):
        """Register a function address -> name mapping"""
        self.address_to_name[addr] = name

    def get_parser(self, func_addr: int, func_name: Optional[str] = None) -> Optional[OutputFunctionParser]:
        """Get the appropriate parser for a function"""
        # Use cached name if available
        if func_name is None:
            func_name = self.address_to_name.get(func_addr, '')

        for parser in self.parsers:
            if parser.can_handle(func_name, func_addr):
                return parser

        return None