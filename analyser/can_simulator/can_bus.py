from json import load
from pathlib import Path
from analyser.mcs_graph import MCSGraph
from analyser.can_simulator.can_component import Component
from analyser.can_simulator.can_message import Message
from analyser.common import Config, IndexedSet, MessageTracer, logger, utils

log = logger(__name__)

class CANBus:
    """
    The `CANBus` class offers functionality similar to a CAN bus. It consists of a buffer holding all the `Messages`
    currently on the bus as well as all the `Components` participating.

    Note: Messages never disappear in this implementation and remain in the buffer forever.

    Since the `CANBus` has an essential role within the Analyser it is implemented `statically` in order
    to eliminate the need of passing instances to all the time and avoiding circular dependencies.
    """
    components: IndexedSet[Component] = IndexedSet()
    buffer: IndexedSet[Message] = IndexedSet()
    msg_types_in_buffer: dict[int, int] = dict() # count which and how many msg_types we have
    _initialized: bool = False


    @classmethod
    def init(cls, path: Path = Path.cwd() / "config.json"):
        """
        Initialise the `CANBus` with a configuration file containing basic information about the components
        participating on this `CANBus`.

        This also initialises the `Config` describing which IO functions are used to write to this bus
        (and therefore need to be hooked) as well how long the msg_ids and msg_data sections are.

        :param path:
        :return:
        """
        if cls._initialized:
            log.warning(f"CANBus.init() called twice... already initialized")
            return

        with open(path, 'r') as f:
            data = load(f)
        components_dir = Path(data['components_dir'])
        symbols = None
        for comp in data['components']:
            component = Component(
                name=comp.get('name', comp['filename']),
                path=Path(components_dir, comp['filename']),
            )

            cid = cls.components.add(component)
            MCSGraph.add_component(component.name, cid=cid, description=comp.get('description', ""))

            if not symbols:
                symbols = utils.extract_msg_id_map(component.path, prefix=data.get('msg_id_prefix', 'MSG_'))

        Config.init(data['var_length'],
            data['input_hooks'],
            data['output_hooks'],
            data.get('msg_id_prefix', 'MSG_'),
            symbols
        )

        cls._initialized = True


    @classmethod
    def write(cls, produced_msg: Message = None, consumed_msgs: set[Message] = None):
        """
        Writes a produced `Message` to the buffer if no identical message is already in it.

        :param produced_msg: The `Message` to be written to the buffer.
        :param consumed_msgs: Set of `Messages` from which the produced_msg was produced. Can be None!
        :return:
        """
        if not cls._initialized:
            log.error(f"Writing to an uninitialized CAN bus...")
            return

        if not produced_msg:
            log.error(f"Got a message with no sender name")
            return

        target = produced_msg.producer_component_name

        if produced_msg:
            if produced_msg.msg_type.is_symbolic():
                log.warning(f"{[produced_msg.producer_component_name]} produced a msg with symbolic type: {produced_msg}")
                return

            produced_msg_type = produced_msg.msg_type.bv.concrete_value

            is_new_message = not cls.buffer.contains(produced_msg)
            produced_msg_id = cls.buffer.add(produced_msg)
            consumed_msgs_ids = [cls.buffer.get_id(m) for m in consumed_msgs]

            MessageTracer.add_production(produced_msg_id, consumed_msgs_ids, target)

            if is_new_message:
                log.info(f"{[target]} produced a new message: {produced_msg}")
                if produced_msg_type in cls.msg_types_in_buffer:
                    cls.msg_types_in_buffer[produced_msg_type] += 1
                else:
                    cls.msg_types_in_buffer[produced_msg_type] = 1

                for component in cls.components:
                    if produced_msg_type in component.consumed_ids and component.is_analysed:
                        log.info(f"Reopening [{component}] to handle a new message: {produced_msg}")
                        component.is_analysed = False # reopen this component as we got a new message for it.

            else:
                log.debug(f"{[produced_msg]} already in buffer")

        cls.update_graph(target, consumed_msgs)


    @classmethod
    def update_graph(cls, target, consumed_msgs):
        """
        Update the MCSGraph with new edges from the consumed message sources to the target component

        :param target: The component the edge should point to
        :param consumed_msgs: The messages holding the edge information.
        :return:
        """
        for consumed_msg in consumed_msgs:
            consumed_msg_id = cls.buffer.get_id(consumed_msg)
            source = consumed_msg.producer_component_name

            message_data = {
                'type': consumed_msg.msg_type_str,
                'msg_type_bv': str(consumed_msg.msg_type.bv),
                'msg_type_constraints': str(consumed_msg.msg_type.constraints),
                'msg_data_bv': str(consumed_msg.msg_data.bv),
                'msg_data_constraints': str(consumed_msg.msg_data.constraints),
                'msg_id': consumed_msg_id,
                'from_unconstrained_run': consumed_msg.from_unconstrained_run
            }

            MCSGraph.add_message_edge(source, target, message_data)


    @classmethod
    def close(cls):
        """
        Close the CANBus, essentially resetting everything.
        :return:
        """
        cls.components.clear()
        cls.buffer.clear()
        cls.msg_types_in_buffer.clear()
        cls.config = Config()
        cls._initialized = False


    @classmethod
    def read_all_msgs_of_types(cls, types: set[int]) -> set[Message]:
        """
        Get all messages with a set of ids (types).
        :param types:
        :return:
        """
        result_set = set()
        for msg in cls.buffer:
            if msg.msg_type.bv.concrete_value in types:
                result_set.add(msg)
        return result_set


    @classmethod
    def number_of_msgs_of_types(cls, types: set[int]) -> int:
        """
        Get the number of messages with a set of ids (types).
        :param types:
        :return:
        """
        total = 0
        for t in types:
            total += cls.msg_types_in_buffer.get(t, 0)
        return total


    @classmethod
    def display(cls):
        """
        Helper method to display the CANBus configuration in a somewhat readable way.
        :return:
        """
        s = "-- CAN-Bus -- \n components:\n"
        for cid, component in cls.components.items():
            s += f" - {component} ({cid})\n"
        return s


    @classmethod
    def __enter__(cls):
        """ Allows the use of `with` statement. """
        if not cls._initialized:
            cls.init()
        return cls


    @classmethod
    def __exit__(cls, exc_type, exc_val, exc_tb):
        """ Allows the use of `with` statement. """
        cls.close()
        return False

    def __repr__(self):
        return self.display()

    def __str__(self):
        return self.display()