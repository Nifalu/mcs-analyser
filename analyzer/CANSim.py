from json import load
from networkx import MultiDiGraph
from pathlib import Path
from dataclasses import dataclass
from analyzer.io_state import IOState
from utils.logger import logger
log = logger(__name__)

@dataclass
class Config:
    default_var_length: int
    input_hooks: list[str]
    output_hooks: list[str]
    leafs: list[str]

class Message:
    def __init__(self, source: int, dest: IOState, msg_data: IOState):
        self.source = source
        self.dest: IOState = dest
        self.msg_data: IOState = msg_data

    def __repr__(self):
        return f"Message(\n  dest={self.dest.name} - {self.dest.constraints},\n  msg_data={self.msg_data.name} - {self.msg_data.constraints})"

class Component:
    def __init__(self, cid, path: Path):
        self.id = cid
        self.path = path
        self.bus = None
        self.expected_inputs = 0

    def config(self) -> Config:
        return self.bus.config

    def send(self, msg: Message):
        if msg.dest.is_symbolic():
            log.critical(f"Message with symbolic destination!\n[{self.id}] -> [{msg.dest.constraints}]\nmsg:{msg}")
            self.bus.graph.add_edge(msg.source, "symbolic destination", destination=msg.dest, msg_data=msg.msg_data)
            return

        # No way there is no getter for this??
        source_node = None
        for node in self.bus.graph.nodes():
            if node == msg.source:
                source_node = node
                break

        # Check if we already got an edge with the same information.
        concrete_dest = msg.dest.bv.concrete_value
        for (source, destination, data) in self.bus.graph.edges(source_node, data=True):
            if destination == concrete_dest and source_node == msg.source:
                edge_msg_data: IOState = data['msg_data']
                if msg.msg_data.equals(edge_msg_data):
                    log.warning("Found identical edge in graph")
                    return

        if msg.msg_data.is_symbolic():
            self.bus.graph.add_edge(
                msg.source,
                concrete_dest,
                type=msg.msg_data.label,
                bv=str(msg.msg_data.bv),
                constraints=msg.msg_data.constraints,
                msg_data=msg.msg_data
            )
        else:
            self.bus.graph.add_edge(
                msg.source,
                concrete_dest,
                type=msg.msg_data.label,
                bv=str(msg.msg_data.bv),
                value=msg.msg_data.bv.concrete_value,
                msg_data=msg.msg_data
            )

        log.info(f"Added edge from {msg.source} to {concrete_dest} with constraints {msg.msg_data.constraints}")
        self.bus.write(msg)



    def read_all(self):
        return self.bus.read_all()

    def __repr__(self):
        return f'Component({self.id}, {self.path})'

    def __str__(self):
        return f'Component({self.id}, {self.path})'


class CANBus:
    def __init__(self, path: Path):
        self.components: list[Component] = []
        self.buffer: list[Message] = []
        self.graph: MultiDiGraph = MultiDiGraph()
        self.config: Config = self._build(path)

    def register(self, component: Component):
        self.components.append(component)
        self.graph.add_node(component.id, path=str(component.path), type='component', component=component)
        component.bus = self

    def write(self, msg: Message):
        self.buffer.append(msg)

    def read_all(self) -> list[Message]:
        return self.buffer

    def _build(self, path: Path) -> Config:
        with open(path, 'r') as f:
            data = load(f)
        components_dir = Path(data['components_dir'])
        leafs = []
        for comp in data['components']:
            if comp['is_leaf']:
                leafs.append(comp['id'])

            component = Component(
                cid=int(comp['id']),
                path=Path(components_dir, comp['filename'])
            )
            self.register(component)

        return Config(data['var_length'],
            data['input_hooks'],
            data['output_hooks'],
            leafs
        )

    def display(self):
        s = "-- CAN-Bus -- \n components:\n"
        for component in self.components:
            s += f" - {component}\n"
        return s

    def __repr__(self):
        return self.display()

    def __str__(self):
        return self.display()

