from analyser.can_simulator import Message
from analyser.io_state import IOState
from utils.logger import logger
log = logger(__name__)


class InputTracker:
    """Tracks consumed inputs during analysis"""
    enumerator = None
    yield_unconstrained = False

    max_inputs_counted = 0
    input_counter = 0

    consumed_messages: set[Message] = set()
    flattened_with_context: list[Message] = []
    component_name = ""


    @classmethod
    def new(cls, component_name: str, input_combination: tuple[Message, ...] = None):
        """Full reset the Tracker"""
        if cls.component_name != component_name:
            cls.max_inputs_counted = 0 # We've got a new component

        cls.component_name = component_name
        cls.consumed_messages.clear()
        cls.flattened_with_context.clear()
        cls.input_counter = 0

        if input_combination:
            cls.yield_unconstrained = False # We've got input
            for msg in input_combination:
                cls.flattened_with_context.append(msg)
                cls.flattened_with_context.append(msg)
        else:
            cls.yield_unconstrained = True

        cls.enumerator = enumerate(cls.flattened_with_context)

    @classmethod
    def soft_reset(cls):
        """
        Reset tracking values to prepare for a new analysis of the same component.
        """
        cls.enumerator = enumerate(cls.flattened_with_context)
        cls.input_counter = 0
        cls.consumed_messages.clear()

    @classmethod
    def get_next_input(cls) -> IOState:
        """Get the next input and track it"""
        cls.input_counter += 1
        cls.max_inputs_counted = max(cls.max_inputs_counted, cls.input_counter)
        if cls.yield_unconstrained:
            return IOState.unconstrained(f"{cls.component_name}_input_{cls.input_counter}")
        try:
            idx, msg = next(cls.enumerator)
            if idx % 2 == 0:
                cls.consumed_messages.add(msg)
                return msg.msg_id
            else:
                return msg.msg_data
        except StopIteration:
            # This should actually never happen as the number of combinations is calculated based
            # the number of unconstrained inputs consumed by this component in an earlier phase.
            raise StopIteration(f"{cls.component_name} requested more inputs than available...")

    @classmethod
    def get_consumed_messages(cls) -> set[Message]:
        return cls.consumed_messages.copy()

