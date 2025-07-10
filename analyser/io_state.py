import \
    claripy
from claripy import simplify as cl_simplify
from claripy import ast as cl_ast
from claripy.solvers import Solver as clSolver
from angr import SimState
from typing import Iterable

# pretty printing
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from analyser.config import \
    Config
from utils.logger import logger
log = logger(__name__)


class IOState:
    """
    Encapsulates the output (or input) of a program.
    """

    def __init__(self,
                 bv: cl_ast.BV,
                 constraints: Iterable[cl_ast.Bool],
                 label=None
                 ):
        self.label = label
        self.bv: cl_ast.BV = bv
        self.constraints: list[cl_ast.Bool] = list(constraints)

    @classmethod
    def unconstrained(
        cls,
        name: str,
        explicit_name=True
    ) -> 'IOState':
        """
        Create an unconstrained IOState with the given name and bit-width.
        """
        bv = cl_ast.bv.BVS(name, Config.default_var_length, explicit_name=explicit_name)
        return cls(bv, [], label='unconstrained')

    @classmethod
    def from_state(
        cls,
        bv: cl_ast.BV,
        state: "SimState",
        *,
        simplify: bool = False,
    ) -> "IOState":

        if bv.symbolic:
            wanted_vars = bv.variables               # e.g. {"scanf_0_14_32"}
            slice_constraints: list[cl_ast.Bool] = []

            for c in state.solver.constraints:
                if not wanted_vars.isdisjoint(c.variables):
                    slice_constraints.append(cl_simplify(c) if simplify else c)

            return cls(bv, slice_constraints, label='symbolic')
        else:
            return cls(bv, [], label='concrete')

    def set_label(self, label: str) -> None:
        self.label = label

    def is_symbolic(self) -> bool:
        """Return True if the encapsulated value is symbolic."""
        return self.bv.symbolic

    def is_concrete(self) -> bool:
        """Return True if the encapsulated value is concrete."""
        return not self.bv.symbolic

    def range(self, solver: clSolver | None = None) -> tuple[int, int]:
        """Return *min*, *max* model of the encapsulated value under its slice."""
        s = solver or clSolver()
        if self.constraints:
            s.add(self.constraints)
            lo = s.min(self.bv)
            hi = s.max(self.bv)
        else:
            lo, hi = 0, (1 << self.bv.length) - 1   # fully unconstrained

        return lo, hi
    
    def equals(self, other: "IOState") -> bool:
        """
        Check if two IOState objects have constraints that define the same solution space.

        Returns True if the IOStates represent equivalent solution spaces, even if they
        use different bitvector variables.
        """
        log.debug(f"Comparing {self.bv} and {other.bv}")
        log.debug(f"with constraints:\n {self.constraints}\n {other.constraints}")

        # Early checks
        if not self.constraints and not other.constraints:
            return True  # Both unconstrained

        if bool(self.constraints) != bool(other.constraints):
            return False  # One constrained, one not

        # Check if both are concrete and compare values
        if self.is_concrete() and other.is_concrete():
            return self.bv.concrete_value == other.bv.concrete_value

        if self.is_concrete() != other.is_concrete():
            return False  # One concrete, one symbolic

        # Check if bitvectors have the same length
        if self.bv.length != other.bv.length:
            return False

        # For symbolic cases, we need to check if the constraints define the same space
        # even if they use different variable names

        # Special case: if both have single-variable constraints only on their respective bvs
        self_vars = set()
        for c in self.constraints:
            self_vars.update(c.variables)

        other_vars = set()
        for c in other.constraints:
            other_vars.update(c.variables)

        # If constraints only reference their respective bitvector variables
        if self_vars == {self.bv} and other_vars == {other.bv}:
            # Create a substitution mapping
            substitution = {self.bv: other.bv}

            # Substitute variables in self.constraints
            substituted_constraints = []
            for c in self.constraints:
                substituted = c.replace(substitution)
                substituted_constraints.append(substituted)

            # Check if substituted constraints are equivalent to other.constraints
            # by checking mutual implication
            solver1 = claripy.Solver()
            solver1.add(substituted_constraints)
            if other.constraints:
                c2_conjunction = claripy.And(*other.constraints) if len(other.constraints) > 1 else other.constraints[0]
                solver1.add(claripy.Not(c2_conjunction))

            if solver1.satisfiable():
                return False

            solver2 = claripy.Solver()
            solver2.add(other.constraints)
            if substituted_constraints:
                c1_conjunction = claripy.And(*substituted_constraints) if len(substituted_constraints) > 1 else substituted_constraints[0]
                solver2.add(claripy.Not(c1_conjunction))

            if solver2.satisfiable():
                return False

            return True

        # General case: check if constraint sets are equivalent
        # This works for the original case but not for renamed variables
        solver1 = claripy.Solver()
        for c in self.constraints:
            solver1.add(c)

        if other.constraints:
            c2_conjunction = claripy.And(*other.constraints) if len(other.constraints) > 1 else other.constraints[0]
            solver1.add(claripy.Not(c2_conjunction))

        if solver1.satisfiable():
            return False

        solver2 = claripy.Solver()
        for c in other.constraints:
            solver2.add(c)

        if self.constraints:
            c1_conjunction = claripy.And(*self.constraints) if len(self.constraints) > 1 else self.constraints[0]
            solver2.add(claripy.Not(c1_conjunction))

        if solver2.satisfiable():
            return False

        return True


    def pretty(self, max_len: int = 96) -> str:
        if self.is_concrete():
            line = f"IOState <{self.bv}> is concrete: {hex(self.bv.args[0])} ({self.bv.length}-bit)"
            return line

        lines = [f"OutputCapsule <{self.bv}> ({self.bv.length}‑bit)"]
        lo, hi = self.range()
        lines.append(f"  range = [{hex(lo)}, {hex(hi)}]")
        lines.append("  slice:")
        for c in self.constraints:
            txt = str(c)
            if len(txt) > max_len:
                txt = txt[:max_len] + "…"
            lines.append("    " + txt)
        return "\n".join(lines)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<OutputCapsule name={self.bv!r} bits={self.bv.length} constraint_length={len(self.constraints)}>"


    def print_rich(self, max_len: int = 96) -> None:
        """
        Pretty-print this IOState to the terminal using *rich*.

        • Concrete capsule  → single-row table with the fixed value.
        • Symbolic capsule  → table with bit-width, min, max plus a panel that
          lists (and truncates) every constraint in the slice.
        """
        console = Console()

        if self.is_concrete():
            table = Table(title=f"IOState <{self.bv}>")
            table.add_column("Bit-width", justify="right")
            table.add_column("Value",     justify="right")
            table.add_row(str(self.bv.length), hex(self.bv.args[0]))
            console.print(table)
            return

        # --------------------------- symbolic --------------------------------
        lo, hi = self.range()

        meta = Table(title=f"IOState <{self.bv}>")
        meta.add_column("Field")
        meta.add_column("Value", justify="right")
        meta.add_row("Bit-width", str(self.bv.length))
        meta.add_row("min",       hex(lo))
        meta.add_row("max",       hex(hi))

        console.print(meta)

        if self.constraints:
            trimmed: list[str] = []
            for c in self.constraints:
                txt = str(c)
                if len(txt) > max_len:
                    txt = txt[:max_len] + "…"
                trimmed.append(txt)

            console.print(
                Panel("\n".join(trimmed), title="Slice constraints", expand=False)
            )