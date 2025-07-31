from json import load
from pathlib import Path

import angr
from networkx import MultiDiGraph

from analyser.can_simulator import Component, Message
from analyser.utils import Config, IndexedSet, MessageTracer, logger
log = logger(__name__)

class CANBus:
    components: IndexedSet[Component] = IndexedSet()
    buffer: IndexedSet[Message] = IndexedSet()
    msg_types_in_buffer: dict[int, int] = dict() # count which and how many msg_types we have
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
            component = Component(
                name=comp['name'],
                path=Path(components_dir, comp['filename']),
            )
            cls._register(component, comp['description'])

            if not symbols:
                symbols = cls.extract_msg_id_map(component.path, prefix="MSG_")

        Config.init(data['var_length'],
            data['input_hooks'],
            data['output_hooks'],
            symbols
        )

        cls._initialized = True

    @classmethod
    def _register(cls, component: Component, description: str):
        cid = cls.components.add(component)
        cls.graph.add_node(component.name, cid=cid, description=description)

    @classmethod
    def write(cls, produced_msg: Message = None, consumed_msgs: set[Message] = None, producer_name: str = None):
        if not cls._initialized:
            log.error(f"Writing to an uninitialized CAN bus...")
            return

        if not produced_msg and not producer_name:
            log.error(f"Got a message with no sender name")
            return

        target = producer_name or produced_msg.producer_component_name

        if produced_msg:
            if produced_msg.msg_type.is_symbolic():
                log.warning(f"{[produced_msg.producer_component_name]} produced a msg with symbolic type: {produced_msg}")
                return

            produced_msg_type = produced_msg.msg_type.bv.concrete_value

            is_new_message = not cls.buffer.contains(produced_msg)
            produced_msg_id = cls.buffer.add(produced_msg)
            consumed_msgs_ids = [cls.buffer.get_id(m) for m in consumed_msgs]

            if consumed_msgs_ids:
                MessageTracer.add_production(produced_msg_id, consumed_msgs_ids, target)

            if is_new_message:
                log.info(f"{[produced_msg.producer_component_name]} produced a new message: {produced_msg}")
                if produced_msg_type in cls.msg_types_in_buffer:
                    cls.msg_types_in_buffer[produced_msg_type] += 1
                else:
                    cls.msg_types_in_buffer[produced_msg_type] = 1

                for component in cls.components:
                    if produced_msg_type in component.subscriptions:
                        log.info(f"Reopening [{target}] to handle a new message: {produced_msg}")
                        component.is_analysed = False # reopen this component as we got a new message for it.

            else:
                log.debug(f"{[produced_msg]} already in buffer")


        for consumed_msg in consumed_msgs:
            continue_outer = False
            consumed_msg_id = cls.buffer.get_id(consumed_msg)
            source = consumed_msg.producer_component_name
            edge_dict = cls.graph.get_edge_data(source, target)
            if edge_dict:
                for key, edge in edge_dict.items():
                    if consumed_msg_id == edge['msg_id']:
                        log.info(f"Message from ({[source]}->{[target]}) is already in the graph")
                        continue_outer = True
                        break
            if continue_outer:
                continue

            cls.graph.add_edge(
                source,
                target,
                type=consumed_msg.msg_type_str,
                msg_type_bv=str(consumed_msg.msg_type.bv),
                msg_type_constraints=str(consumed_msg.msg_type.constraints),
                msg_data_bv=str(consumed_msg.msg_data.bv),
                msg_data_constraints=str(consumed_msg.msg_data.constraints),
                msg_id = consumed_msg_id
            )
            log.debug(f"Added edge between {[source]} -> {[target]} with message of type {[consumed_msg.msg_type_str]}")

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
        cls.components.clear()
        cls.buffer.clear()
        cls.msg_types_in_buffer.clear()
        cls.graph.clear()
        cls.config = Config()
        cls._initialized = False

    @classmethod
    def read_all_msgs_of_types(cls, types: set[int]) -> set[Message]:
        result_set = set()
        for msg in cls.buffer:
            if msg.msg_type.bv.concrete_value in types:
                result_set.add(msg)
        return result_set

    @classmethod
    def number_of_msgs_of_types(cls, types: set[int]) -> int:
        total = 0
        for t in types:
            total += cls.msg_types_in_buffer.get(t, 0)
        return total

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