import \
    claripy
from claripy import simplify as cl_simplify
from claripy import ast as cl_ast
from claripy.solvers import Solver as clSolver
from angr import SimState
from typing import Iterable

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
                 label: str = None,
                 ):
        self.label = label
        self.bv: cl_ast.BV = bv
        self.constraints: list[cl_ast.Bool] = list(constraints)
        self._hash = None

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

    def evaluate_n_values(self, n: int) -> Iterable[int]:
        solver = clSolver()
        solver.add(self.constraints)

        if solver.satisfiable():
            return solver.eval(self.bv, n, exact=True)
        else:
            return []
    
    def equals(self, other: "IOState") -> bool:
        """
        Check if two IOState objects have constraints that define the same solution space.

        Returns True if the IOStates represent equivalent solution spaces, even if they
        use different bitvector variables or have different lengths (if one is derived
        from the other through operations like extraction, extension, etc.).
        """
        log.debug(f"Comparing {self.bv} and {other.bv}")
        log.debug(f"with constraints:\n {self.constraints}\n {other.constraints}")

        # if both are concrete and have the same value, they are equal
        if self.is_concrete() and other.is_concrete():
            return self.bv.concrete == other.bv.concrete_value

        # If just one is concrete, they can't be equal
        if self.is_concrete() != other.is_concrete():
            return False

        # Case where both bv have same length:
        if self.bv.length == other.bv.length:

            # If both are unconstrained, they must be equal
            if not self.constraints and not other.constraints:
                return True

            # If just one is constrained, they can't be equal
            if bool(self.constraints) != bool(other.constraints):
                return False
            
        
        """Check if two constraint sets mutually imply each other."""
        # Check if self.constraints implies other.constraints
        solver1 = claripy.Solver()
        solver1.add(self.constraints)
        if other.constraints:
            c2_conjunction = claripy.And(*other.constraints) if len(other.constraints) > 1 else other.constraints[0]
            solver1.add(claripy.Not(c2_conjunction))

        if solver1.satisfiable():
            return False

        # Check if other.constraints implies self.constraints
        solver2 = claripy.Solver()
        solver2.add(other.constraints)
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

    def __repr__(self) -> str:
        return f"<IOState name={self.bv!r} bits={self.bv.length} constraint_length={len(self.constraints)}>"

    def __str__(self) -> str:
        return f"<IOState name={self.bv!r} bits={self.bv.length} constraint_length={len(self.constraints)}>"

    def __eq__(self, other) -> bool:
        if not isinstance(other, IOState):
            return False
        return self.equals(other)

    def __hash__(self) -> int:
        """
        Compute a hash for this IOState.

        Note: This hash function is designed to be consistent with equals() but
        may have collisions. Two IOStates that are equal according to equals()
        will have the same hash, but two IOStates with the same hash may not be equal.
        """
        if self._hash is not None:
            return self._hash

        if self.is_concrete():
            # For concrete values, hash the value and the bit length
            self._hash = hash((self.bv.concrete_value, self.bv.length, "concrete"))
        else:
            # For symbolic values, we can't easily create a perfect hash that's
            # consistent with our semantic equality check. We'll use a hash that
            # ensures equal objects have the same hash, but may have collisions.

            # Hash based on bit length and whether it has constraints
            basic_hash = hash((
                self.bv.length,
                len(self.constraints),
                bool(self.constraints),
                "symbolic"
            ))

            # Add some constraint structure information to reduce collisions
            if self.constraints:
                # Sort constraints by their string representation for consistency
                constraint_strs = sorted(str(c) for c in self.constraints)
                # Use first few characters of each constraint
                constraint_sample = "".join(s[:20] for s in constraint_strs[:10])
                constraint_hash = hash(constraint_sample)
                self._hash = hash((basic_hash, constraint_hash))
            else:
                self._hash = basic_hash

        return self._hash


