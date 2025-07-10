from json import load
from pathlib import Path
from networkx import MultiDiGraph

from analyser.can_simulator.component import Component
from analyser.can_simulator.message import Message
from analyser.config import Config
from utils.logger import logger
log = logger(__name__)

class CANBus:
    components: dict[int, Component] = {}
    buffer: list[Message] = []
    _initialized: bool = False
    graph = MultiDiGraph()

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
        cls.components[component.cid] = component
        cls.graph.add_node(component.name, component=component)

    @classmethod
    def write(cls, msg: Message):
        if not cls._initialized:
            log.warning(f"Writing to an uninitialized CAN bus...")
        try:
            source_name = cls.components[msg.source].name
            dest_name = cls.components[msg.dest].name
        except KeyError as e:
            log.error(f"Unable to find components for edge ({msg.source} -> {msg.dest}):\n{e}")
            return

        # Check if we already got an edge with the same information.
        edge_dict = cls.graph.get_edge_data(source_name, dest_name)
        if edge_dict:
            for key, edge in edge_dict.items():
                if msg.msg_data.equals(edge['msg_data']):
                    log.debug(f"Found edge ({source_name} -> {dest_name}) with identical constraints")
                    return

        if msg.msg_data.is_symbolic():
            cls.graph.add_edge(
                source_name,
                dest_name,
                type=msg.msg_data.label,
                bv=str(msg.msg_data.bv),
                constraints=msg.msg_data.constraints,
                msg_data=msg.msg_data
            )
        else:
            cls.graph.add_edge(
                source_name,
                dest_name,
                type=msg.msg_data.label,
                bv=str(msg.msg_data.bv),
                value=msg.msg_data.bv.concrete_value,
                msg_data=msg.msg_data
            )
        log.info(f"Added edge ({source_name} -> {dest_name}) BV: {msg.msg_data.bv}, constraints: {msg.msg_data.constraints}")
        cls.buffer.append(msg)

    @classmethod
    def close(cls):
        cls.components = {}
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
        for cid, component in cls.components.items():
            s += f" - {component} ({cid})\n"
        return s

    @classmethod
    def __enter__(cls):
        if not cls._initialized:
            cls.init()
        return cls

    @classmethod
    def __exit__(cls, exc_type, exc_val, exc_tb):
        return False

    def __repr__(self):
        return self.display()

    def __str__(self):
        return self.display()