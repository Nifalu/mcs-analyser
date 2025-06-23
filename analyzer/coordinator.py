from networkx import \
    DiGraph
from schnauzer import \
    VisualizationClient

from analyzer.io_state import \
    IOState, \
    IOConfig, \
    Component, \
    IOSnapshot
from pathlib import Path
import json

from dataclasses import dataclass

from analyzer.simple_analyzer import \
    SimpleAnalyzer
from utils.logger import logger
log = logger(__name__)


@dataclass
class Config:
    default_var_length: int
    input_hooks: list[str]
    output_hooks: list[str]

class CANMessage:
    def __init__(self, dest: IOState, msg_data: IOState):
        self.dest: IOState = dest
        self.msg_data: IOState = msg_data

    def __repr__(self):
        return f"CANMessage(\n  dest={self.dest},\n  msg_data={self.msg_data})"

class CANNode:
    def __init__(self, cid, path: Path):
        self.id = cid
        self.path = path
        self.bus = None

    def config(self) -> Config:
        return self.bus.config

    def send(self, msg: CANMessage):
        if msg.dest.is_symbolic():
            log.critical(f"Message with symbolic destination!\n[{self.id}] -> [{msg.dest.constraints}]\nmsg:{msg}")
        self.bus.write(msg)

    def read_all(self):
        return self.bus.read_all()

    def __repr__(self):
        return f'CANNode({self.id}, {self.path})'

    def __str__(self):
        return f'CANNode({self.id}, {self.path})'


class CANBus:
    def __init__(self, path: Path):
        self.nodes: list[CANNode] = []
        self.buffer: list[CANMessage] = []
        self.config: Config = self._build(path)

    def register(self, node: CANNode):
        self.nodes.append(node)
        node.bus = self

    def write(self, msg: CANMessage):
        self.buffer.append(msg)

    def read_all(self) -> list[CANMessage]:
        return self.buffer

    def _build(self, path: Path) -> Config:
        with open(path, 'r') as f:
            data = json.load(f)
        components_dir = Path(data['components_dir'])
        for comp in data['components']:
            node = CANNode(
                cid=int(comp['id']),
                path=Path(components_dir, comp['filename'])
            )
            self.register(node)

        return Config(data['var_length'],
               data['input_hooks'],
               data['output_hooks']
        )

    def display(self):
        s = "-- CAN-Bus -- \n subscribers:\n"
        for node in self.nodes:
            s += f" - {node}\n"
        return s

    def __repr__(self):
        return self.display()

    def __str__(self):
        return self.display()


class Coordinator:

    def __init__(self,
                 config_path: Path = Path.cwd() / "config.json",
                 ):
        self.graph = None
        self.config = _parse(config_path)

    def run(self):
        self.graph = DiGraph() # Reset the graph

        queue: list[IOSnapshot] = []

        # Start analyzing the leaf components, i.e. components that do not depend on others.
        for cid in self.config.leaf_components:
            arbitrary_input = IOState.unconstrained(f"input_{cid}", 64)
            c = self.config.components[cid]
            sa = SimpleAnalyzer(c.path, [arbitrary_input], self.config)
            snapshot = sa.analyze()
            snapshot.add_input(0, arbitrary_input)
            snapshot.print_rich()
            queue.append(snapshot)
            self.graph.add_node(f"input_{cid}", type="input")
            self.graph.add_node(snapshot.name, type="component")
            self.graph.add_edge(f"input_{cid}", snapshot.name, type="symbolic")

        while queue:
            origin_snapshot = queue.pop(0)
            for cid, values in origin_snapshot.outputs.items():
                if cid in self.config.leaf_components:
                    raise ValueError(f"Unexpected leaf component {cid} in queue. This should not happen.")
                if cid == 0:  # We have reached the root
                    self.graph.add_node(f"output_{cid}", type="output")
                    for v in values:
                        t = "symbolic" if v.is_symbolic else "concrete"
                        self.graph.add_edge(origin_snapshot.name, f"output_{cid}", type=t)
                    continue

                c = self.config.components[cid]
                sa = SimpleAnalyzer(c.path, values, self.config)
                new_snapshot = sa.analyze()
                self.graph.add_node(new_snapshot.name, type="component")
                for v in values:
                    new_snapshot.add_input(cid, v)
                    t = "symbolic" if v.is_symbolic else "concrete"
                    self.graph.add_edge(origin_snapshot.name, new_snapshot.name, type=t)
                new_snapshot.print_rich()
                queue.append(new_snapshot)

        vc = VisualizationClient()
        type_color_map = {
            # Nodes
            "input": "#9FE2BF",
            "output": "#CCCCFF",
            "component": "#6495ED",
            # Edges
            "symbolic": "#FFBF00",
            "concrete": "#DE3163"
        }
        vc.send_graph(self.graph, type_color_map=type_color_map)










def _parse(path: Path) -> IOConfig:
    """
    Parse the configuration file to get the components and their mappings.
    """
    import json
    with open(path, 'r') as f:
        data = json.load(f)
    components_dir = Path(data['components_dir'])
    config = IOConfig({}, set())
    for comp in data['components']:
        c = Component(
            path=Path(components_dir, comp['filename']),
            id=int(comp['id']),
            is_leaf=comp.get('is_leaf', True),
            input_mapping=comp.get('input_mapping', {})
        )

        if c.is_leaf:
            config.leaf_components.add(c.id)

        config.components[c.id] = c

    return config