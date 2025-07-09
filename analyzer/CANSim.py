from json import load
from networkx import MultiDiGraph
from pathlib import Path

from analyzer.config import \
    Config
from analyzer.io_state import IOState
from utils.logger import logger
log = logger(__name__)

class Message:
    def __init__(self, source: int, destination: int, msg_data: IOState):
        self.source = source
        self.dest = destination
        self.msg_data: IOState = msg_data

    def __repr__(self):
        return f"Message({self.source} -> {self.dest}) BV: {self.msg_data.bv}, constraints: {self.msg_data.constraints}"

    def __str__(self):
        return f"Message({self.source} -> {self.dest}) BV: {self.msg_data.bv}, constraints: {self.msg_data.constraints}"

class Component:
    def __init__(self, name: str, path: Path, cid: int):
        self.name = name
        self.path = path
        self.cid = cid
        self.expected_inputs = 0

    def __repr__(self):
        return f'Component({self.name}, id: {self.cid}, path: {self.path})'

    def __str__(self):
        return f'Component({self.name}, id: {self.cid}, path: {self.path})'


class CANBus:
    components: list[Component] = []
    buffer: list[Message] = []
    graph: MultiDiGraph = MultiDiGraph()
    _initialized: bool = False

    @classmethod
    def init(cls, path: Path = Path.cwd() / "config.json"):
        if cls._initialized:
            log.warning(f"CANBus.init() called twice... already initialized")
            return

        with open(path, 'r') as f:
            data = load(f)
        components_dir = Path(data['components_dir'])
        for comp in data['components']:

            component = Component(
                name=comp['name'],
                cid=int(comp['id']),
                path=Path(components_dir, comp['filename'])
            )
            cls._register(component)

        Config.init(data['var_length'],
            data['input_hooks'],
            data['output_hooks']
        )

        cls._initialized = True

    @classmethod
    def _register(cls, component: Component):
        cls.components.append(component)
        cls.graph.add_node(component.cid, component=component)

    @classmethod
    def write(cls, msg: Message):
        if not cls._initialized:
            log.warning(f"Writing to an uninitialized CAN bus...")

        # Check if we already got an edge with the same information.
        edge_dict = cls.graph.get_edge_data(msg.source, msg.dest)
        if edge_dict:
            for key, edge in edge_dict.items():
                if msg.msg_data.equals(edge['msg_data']):
                    log.debug(f"Found edge ({msg.source} -> {msg.dest}) with identical constraints")
                    return

        if msg.msg_data.is_symbolic():
            cls.graph.add_edge(
                msg.source,
                msg.dest,
                type=msg.msg_data.label,
                bv=str(msg.msg_data.bv),
                constraints=msg.msg_data.constraints,
                msg_data=msg.msg_data
            )
        else:
            cls.graph.add_edge(
                msg.source,
                msg.dest,
                type=msg.msg_data.label,
                bv=str(msg.msg_data.bv),
                value=msg.msg_data.bv.concrete_value,
                msg_data=msg.msg_data
            )
        log.info(f"Added edge ({msg.source} -> {msg.dest}) BV: {msg.msg_data.bv}, constraints: {msg.msg_data.constraints}")
        cls.buffer.append(msg)

    @classmethod
    def close(cls):
        cls.components = []
        cls.buffer = []
        cls.graph.clear()
        cls.config = Config()
        cls._initialized = False

    @classmethod
    def read_all(cls) -> list[Message]:
        return cls.buffer

    @classmethod
    def display(cls):
        s = "-- CAN-Bus -- \n components:\n"
        for component in cls.components:
            s += f" - {component}\n"
        return s

    @classmethod
    def __enter__(cls):
        print("enter")
        if not cls._initialized:
            cls.init()
        return cls

    @classmethod
    def __exit__(cls, exc_type, exc_val, exc_tb):
        print("exit")
        return False

    def __repr__(self):
        return self.display()

    def __str__(self):
        return self.display()

