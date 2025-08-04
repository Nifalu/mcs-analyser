import claripy
from angr import SimState
from typing import Iterable

from analyser.common.config import Config
from analyser.common.logger import logger
log = logger(__name__)


class IOState:
    def __init__(self, bv: claripy.ast.BV, constraints: Iterable[claripy.ast.Bool]):
        """
        A container to create and store a bitvectors and their constraints.

        :param bv: a claripy bitvector
        :param constraints: an iterable of constraints
        """
        self.bv: claripy.ast.BV = bv
        self.constraints: list[claripy.ast.Bool] = list(constraints)
        self._hash = None


    @classmethod
    def unconstrained(cls, name: str, explicit_name=True) -> 'IOState':
        """
        Create an unconstrained IOState with the given name and bit-width.
        """
        bv = claripy.ast.bv.BVS(name, Config.default_var_length, explicit_name=explicit_name)
        return cls(bv, [])


    @classmethod
    def from_state(cls, bv: claripy.ast.BV, state: "SimState", *, simplify: bool = False) -> "IOState":
        """
        Create an IOState from a specific bitvector and its constraints from an `angr.SimState`
        :param bv:
        :param state:
        :param simplify:
        :return:
        """
        constraints: list[claripy.ast.Bool] = []
        if bv.symbolic:
            wanted_vars = bv.variables
            for c in state.solver.constraints:
                if not wanted_vars.isdisjoint(c.variables):
                    constraints.append(claripy.simplify(c) if simplify else c)
        return cls(bv, constraints)


    def is_symbolic(self) -> bool:
        """Return True if the encapsulated value is symbolic."""
        return self.bv.symbolic


    def is_concrete(self) -> bool:
        """Return True if the encapsulated value is concrete."""
        return not self.bv.symbolic

    
    def equals(self, other: "IOState") -> bool:
        """
        Check if two IOState objects have constraints that define the same solution space.

        Returns True if the IOStates represent equivalent solution spaces, even if they
        use different bitvector variables or have different lengths (if one is derived
        from the other through operations like extraction, extension, etc.).

        Since we compare solution spaces from two IOStates which may have different variable names,
        this entire comparison probably isn't "correct". If we have two sets of bitvectors and for each bitvector
        in set A there is an "equal" bitvector in set B, if those bitvectors aren't named identically this function
        currently can't detect that. Then again, just because the bitvectors of both sets are identical they don't have
        to represent the same thing. So maybe the naming is still relevant. I'm sure some guy will come up with a better
        solution to this. For now, it is enough to catch the simple cases to reduce path explosion at least a bit.
        """

        # if both are concrete and have the same value, they are equal
        if self.is_concrete() and other.is_concrete():
            return self.bv.concrete_value == other.bv.concrete_value

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


    def __repr__(self) -> str:
        return f"IOState(bv={self.bv}, constraints={self.constraints})"


    def __str__(self) -> str:
        return f"IOState(bv={self.bv}, constraints={self.constraints})"


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


