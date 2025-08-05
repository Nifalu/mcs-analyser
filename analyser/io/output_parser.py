import angr
import re
import claripy
from typing import Optional
from abc import ABC, abstractmethod
from angr import SimUnsatError
from analyser.common import logger
log = logger(__name__)

"""
This module provides individual output function parsers for different output functions.
With angr hooks we could technically just hook the output functions (similarly as input functions are hooked)
and then retrieve the arguments automatically. However since we don't know in advance how many arguments the
output functions might have, we kinda have to retrieve them manually.
"""


class OutputFunctionParser(ABC):
    """Base class for parsing output function arguments"""


    @abstractmethod
    def can_handle(self, func_name: str) -> bool:
        """Check if this parser can handle the given function"""
        pass


    @abstractmethod
    def parse_arguments(self, state: angr.SimState) -> list[claripy.ast.BV]:
        """Extract arguments from the function call"""
        pass


    @staticmethod
    def get_n_args(state: angr.SimState, num_args):
        """
        Get n arguments according to the calling convention
        :param state:
        :param num_args:
        :return:
        """
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



class PrintfParser(OutputFunctionParser):
    """
    OutputFunctionParser for printf functions.
    """

    def __init__(self):
        self.printf_functions = {
            'printf', 'fprintf', 'sprintf', 'snprintf',
            'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf'
        }


    def can_handle(self, func_name: str) -> bool:
        """
        Check if this parser can handle the given function
        :param func_name:
        :return:
        """
        return func_name in self.printf_functions


    def parse_arguments(self, state: angr.SimState) -> list[claripy.ast.BV]:
        """
        Try to extract the arguments from the call state
        :param state:
        :return:
        """
        format_str_ptr = self._get_format_string_ptr(state)
        try:
            format_str = state.solver.eval(state.memory.load(format_str_ptr, 1024), cast_to=bytes)
            format_str = format_str.split(b'\x00')[0].decode('utf-8', errors='ignore')
            num_args = self._count_format_specifiers(format_str)
            log.debug(f"Format string: '{format_str}', expecting {num_args} arguments")
        except SimUnsatError:
            num_args = 2
            log.warning("Could not parse format string, assuming 2 arguments")

        return self.get_n_args(state, num_args)


    def _get_format_string_ptr(self, state):
        """
        Try to extract the format string from the call state
        :param state:
        :return:
        """
        arch_name = state.arch.name.lower()
        if 'x86' in arch_name and '64' not in arch_name:
            log.warning("in x86 architecture")
            return state.memory.load(state.regs.esp + 4, 4)
        elif 'amd64' in arch_name or 'x86_64' in arch_name:
            return state.regs.rdi
        else:
            raise NotImplementedError(f"Architecture {arch_name} not supported")


    @staticmethod
    def _count_format_specifiers(format_str):
        """
        Count the number of format specifiers in the format string
        :param format_str:
        :return:
        """
        format_str = format_str.replace('%%', '')
        count = len(re.findall(r'%', format_str))
        count += format_str.count('*')
        return count



class OutputParserRegistry:

    def __init__(self):
        """
        Registry for output function parsers.
        """
        self.parsers: list[OutputFunctionParser] = [
            PrintfParser(),
        ]
        self.address_to_name = {}  # Cache for address -> function name mapping


    def register_parser(self, parser: OutputFunctionParser):
        """
        Register additional output parsers
        :param parser:
        :return:
        """
        self.parsers.append(parser)


    def register_function(self, addr: int, name: str):
        """
        Register a new function address and its name.
        This is later used to look up the function names based
        on an address in order to find the matching parser.

        :param addr:
        :param name:
        :return:
        """
        self.address_to_name[addr] = name


    def get_parser(self, func_addr: int) -> Optional[OutputFunctionParser]:
        """
        Retrieve the parser for the given function address.

        :param func_addr:
        :return:
        """
        func_name = self.address_to_name.get(func_addr, '')

        for parser in self.parsers:
            if parser.can_handle(func_name):
                return parser
        log.warning(f"No parser for address {func_addr:x} ({self.address_to_name.get(func_addr)})")
        return None