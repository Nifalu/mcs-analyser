from dataclasses import dataclass
from typing import \
    AnyStr, \
    Optional

from angr import SimState


@dataclass
class IOValue:
    name: str
    expression: AnyStr
    is_symbolic: bool
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    concrete_value: Optional[int] = None

    @classmethod
    def from_expr(cls, name: str, expr, state: SimState):
        """
        Create a Value object from an expression.
        :param name: The name of the value.
        :param expr: The expression to create the value from.
        :param state: The state to use for creating the value.
        :return: A Value object.
        """
        is_symbolic = state.solver.symbolic(expr)
        result = cls(
            name=name,
            expression=expr,
            is_symbolic=is_symbolic,
        )

        if is_symbolic:
            try:
                result.min_value = state.solver.min(expr)
                result.max_value = state.solver.max(expr)
            except Exception:
                pass
        else:
            result.concrete_value = state.solver.eval(expr)
            result.min_value = result.concrete_value
            result.max_value = result.concrete_value

        return result

    def is_range(self) -> bool:
        """
        Check if the value is a range.
        :return: True if the value is a range, False otherwise.
        """
        return self.min_value != self.max_value

    def is_concrete(self) -> bool:
        """
        Check if the value is concrete.
        :return: True if the value is concrete, False otherwise.
        """
        return self.concrete_value is not None

    def is_unconstrained(self) -> bool:
        """
        Check if the value is unconstrained.
        :return: True if the value is unconstrained, False otherwise.
        """
        return self.is_symbolic and self.min_value is None and self.max_value is None

    def __repr__(self) -> str:
        """
        Return a string representation of the Value object.
        :return: A string representation of the Value object.
        """
        return f"Value(name={self.name}, expression={self.expression}, is_symbolic={self.is_symbolic}, min_value={self.min_value}, max_value={self.max_value}, concrete_value={self.concrete_value})"

    def __str__(self) -> str:
        """
        Return a string representation of the Value object.
        :return: A string representation of the Value object.
        """
        return f"Value(name={self.name}, expression={self.expression}, is_symbolic={self.is_symbolic}, min_value={self.min_value}, max_value={self.max_value}, concrete_value={self.concrete_value})"



@dataclass
class IOSnapshot:

    inputs: list[IOValue]
    outputs: list[IOValue]

