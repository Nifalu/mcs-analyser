import \
    itertools
from dataclasses import \
    dataclass
from pathlib import Path

from claripy import simplify as cl_simplify
from claripy import ast as cl_ast
from claripy.solvers import Solver as clSolver
from angr import SimState
from typing import \
    Iterable, \
    Callable

# pretty printing
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align

from utils.logger import logger
log = logger(__name__)


@dataclass
class Component:
    path: Path
    id: int
    is_leaf: bool
    input_mapping: dict[int, int]

@dataclass
class IOConfig:
    components: dict[int, Component]
    leaf_components: set[int]

class IOState:
    """
    Encapsulates the output (or input) of a program.
    """

    def __init__(self,
                 name: str,
                 bv: cl_ast.BV,
                 constraints: Iterable[cl_ast.Bool],
                 ):
        self.name = name
        self.bv: cl_ast.BV = bv
        self.constraints: list[cl_ast.bool] = list(constraints)

    @classmethod
    def unconstrained(
        cls,
        name: str,
        length: int,
    ) -> 'IOState':
        """
        Create an unconstrained IOState with the given name and bit-width.
        """
        bv = cl_ast.bv.BVS(name, length)
        return cls(name, bv, [])

    @classmethod
    def from_state(
        cls,
        name: str,
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

            return cls(name, bv, slice_constraints)
        else:
            return cls(name, bv, [])


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

    def pretty(self, max_len: int = 96) -> str:
        if self.is_concrete():
            line = f"IOState <{self.name}> is concrete: {hex(self.bv.args[0])} ({self.bv.length}-bit)"
            return line

        lines = [f"OutputCapsule <{self.name}> ({self.bv.length}‑bit)"]
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
        return f"<OutputCapsule name={self.name!r} bits={self.bv.length} constraint_length={len(self.constraints)}>"


    def print_rich(self, max_len: int = 96) -> None:
        """
        Pretty-print this IOState to the terminal using *rich*.

        • Concrete capsule  → single-row table with the fixed value.
        • Symbolic capsule  → table with bit-width, min, max plus a panel that
          lists (and truncates) every constraint in the slice.
        """
        console = Console()

        if self.is_concrete():
            table = Table(title=f"IOState <{self.name}>")
            table.add_column("Bit-width", justify="right")
            table.add_column("Value",     justify="right")
            table.add_row(str(self.bv.length), hex(self.bv.args[0]))
            console.print(table)
            return

        # --------------------------- symbolic --------------------------------
        lo, hi = self.range()

        meta = Table(title=f"IOState <{self.name}>")
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

class IOSnapshot:
    """
    A point-in-time view of all symbolic I/O for one binary execution.

    Attributes
    ----------
    inputs  : list[IOState]
        Capsules that describe every symbolic (or concrete) *input* used.
    outputs : list[IOState]
        Capsules that describe every symbolic (or concrete) *output* produced.
    """

    def __init__(
        self,
        name: str = "IOSnapshot",
        inputs: dict[Component, list[IOState]] = None,
        outputs: dict[Component, list[IOState]] = None,
    ):
        self.name: str = name
        self.inputs: dict[int, list[IOState]] = inputs or dict()
        self.outputs: dict[int, list[IOState]] = outputs or dict()

    # ------------------------------------------------------------------ #
    # Mutators
    # ------------------------------------------------------------------ #
    def add_input(self, cid: int, ios: IOState) -> None:
        """
        Add a single input IOState to the snapshot, associated with the given component.
        """
        if cid not in self.inputs.keys():
            self.inputs[cid] = []
        self.inputs[cid].append(ios)

    def add_output(self, cid: int, ios: IOState) -> None:
        """
        Add a single output IOState to the snapshot, associated with the given component.
        """
        if cid not in self.outputs.keys():
            self.outputs[cid] = []
        self.outputs[cid].append(ios)

    # ------------------------------------------------------------------ #
    # Pretty-printing with rich
    # ------------------------------------------------------------------ #
    def print_rich(self, max_len: int = 96) -> None:
        """
        Show a colourised snapshot:

        • first table lists every input and output with bit-width & range / value
        • below it, one constraint panel per IOState that carries constraints
        """
        console = Console()
        console.rule("[bold cyan] " + self.name)

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Role")
        table.add_column("Name")
        table.add_column("Bits", justify="right")
        table.add_column("Range / Value", justify="right")

        def _row(role: str, states: list[IOState]):
            for state in states:
                if state.is_concrete():
                    val = hex(int(state.bv.args[0]))
                    table.add_row(role, state.name, str(state.bv.length), val)
                else:
                    lo, hi = state.range()
                    table.add_row(role, state.name, str(state.bv.length),
                                  f"[{hex(lo)}, {hex(hi)}]")

        for cid in self.inputs:
            _row(f"[green] {cid} → in", self.inputs[cid])
        for cid in self.outputs:
            _row(f"[red] out → {cid}", self.outputs[cid])

        console.print(Align.center(table))

        # constraint panels
        for ios in itertools.chain(*self.inputs.values(), *self.outputs.values()):
            if ios.constraints:
                trimmed = []
                for c in ios.constraints:
                    txt = str(c)
                    if len(txt) > max_len:
                        txt = txt[:max_len] + "…"
                    trimmed.append(txt)
                console.print(
                    Align.center(
                    Panel("\n".join(trimmed),
                          title=f"Constraints on {ios.name}",
                          expand=False)
                    )
                )

    # ------------------------------------------------------------------ #
    # Convenience helpers
    # ------------------------------------------------------------------ #
    def __iter__(self):
        yield from self.inputs
        yield from self.outputs

    def __repr__(self) -> str:
        return (f"<IOSnapshot inputs={len(self.inputs)} "
                f"outputs={len(self.outputs)}>")
