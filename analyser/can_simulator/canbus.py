from json import load
from pathlib import Path

import \
    angr
from networkx import MultiDiGraph

from analyser.can_simulator.component import Component
from analyser.can_simulator.message import Message
from analyser.config import Config
from analyser.indexed_set import \
    IndexedSet
from utils.logger import logger
log = logger(__name__)

class CANBus:
    components: list[Component] = []
    buffer: IndexedSet = IndexedSet()
    msg_types_in_buffer: set[int] = set()
    graph = MultiDiGraph()
    _initialized: bool = False

    @classmethod
    def init(cls, path: Path = Path.cwd() / "config.json"):
        if cls._initialized:
            log.warning(f"CANBus.init() called twice... already initialized")
            return

        with open(path, 'r') as f:
            data = load(f)
        components_dir = Path(data['components_dir'])
        symbols = None
        for comp in data['components']:
            path = Path(components_dir, comp['filename'])

            virtual = not path or not path.is_file()

            component = Component(
                name=comp['name'],
                path=Path(components_dir, comp['filename']),
                is_virtual=virtual
            )
            cls._register(component)

            if not virtual and not symbols:
                symbols = cls.extract_msg_id_map(component.path, prefix="MSG_")

        Config.init(data['var_length'],
            data['input_hooks'],
            data['output_hooks'],
            symbols
        )

        cls._initialized = True

    @classmethod
    def _register(cls, component: Component):
        cls.components.append(component)
        cls.graph.add_node(component.name)

    @classmethod
    def write(cls, produced_msg: Message, consumed_msgs: set[Message]):
        if not cls._initialized:
            log.warning(f"Writing to an uninitialized CAN bus...")

        target = produced_msg.producer_component_name
        if not consumed_msgs:
            if not produced_msg in cls.buffer:
                if produced_msg.msg_type.is_concrete:
                    log.info(f"{[target]} produced a new message: {produced_msg}")
                    cls.buffer.add(produced_msg)
                    cls.msg_types_in_buffer.add(produced_msg.msg_type.bv.concrete_value)
            else:
                log.debug(f"{[target]} produced an already existing message: {produced_msg}")

        else:
            # Component consumed at least 1 message to produce another
            for consumed_msg in consumed_msgs:
                msg_id = cls.buffer.add(produced_msg)
                source = consumed_msg.producer_component_name
                edge_dict = cls.graph.get_edge_data(source, target)
                if edge_dict:
                    for key, edge in edge_dict.items():
                        if msg_id == edge['msg_id']:
                            log.info(f"Message from ({[source]}->{[target]}) is already in the graph")
                            return

                cls.graph.add_edge(
                    source,
                    target,
                    type=consumed_msg.msg_type_str,
                    msg_type_bv=str(consumed_msg.msg_type.bv),
                    msg_type_constraints=str(consumed_msg.msg_type.constraints),
                    msg_data_bv=str(consumed_msg.msg_data.bv),
                    msg_data_constraints=str(consumed_msg.msg_data.constraints),
                    msg_id = msg_id
                )
                log.info(f"Added edge between {[source]} -> {[target]}) Message of type {[consumed_msg.msg_type_str]}")
                cls.buffer.add(consumed_msg)


    @staticmethod
    def extract_msg_id_map(binary_path, prefix) -> dict[int, str]:
        try:
            proj = angr.Project(binary_path, auto_load_libs=False)
        except Exception as e:
            log.error(f"Error loading binary: {e} during symbol extraction")
            return {}

        log.debug(f"Loaded binary: {binary_path}")

        results = {}

        for symbol in proj.loader.main_object.symbols:
            if not symbol.name:
                continue

            # Check if symbol starts with prefix (with or without underscore)
            clean_name = symbol.name.lstrip('_')
            if clean_name.startswith(prefix):
                if hasattr(symbol, 'size') and symbol.size > 0:
                    value = proj.loader.memory.unpack_word(symbol.rebased_addr, size=8)
                    log.info(f"Extracted {clean_name} = {value} (0x{value:x})")  # Print both decimal and hex
                    if value in results:
                        raise(ValueError(f"Multiple Message ID's with the same name detected: {value}"))
                    results[value] = clean_name
        return results

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