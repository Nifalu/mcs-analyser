from itertools import product, permutations
from math import factorial
from analyser.can_simulator import Message, CANBus, Component
from analyser.common import logger, IOState
log = logger(__name__)


class InputTracker:
    """
    Keeps track of which inputs a component should consume next.
    """
    enumerator = None
    yield_unconstrained = False

    max_inputs_counted = 0
    input_counter = 0

    consumed_messages: set[Message] = set()
    flattened_with_context: list[Message] = []
    component: Component = None


    @classmethod
    def new(cls, component: Component, input_combination: tuple[Message, ...] = None):
        """
        Prepare (reset) the tracker for a new combination or component.
        :param component:
        :param input_combination:
        :return:
        """
        if cls.component is not None and cls.component.name != component.name:
            cls.max_inputs_counted = 0 # We've got a new component

        cls.component = component
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
        """
        Get the next input for the current component and track which messages were consumed.
        :return:
        """
        cls.input_counter += 1
        cls.max_inputs_counted = max(cls.max_inputs_counted, cls.input_counter)
        if cls.yield_unconstrained:
            log.debug(f"Yield unconstrained {cls.component.name}_input_{cls.input_counter}")
            next_input = IOState.unconstrained(f"{cls.component.name}_input_{cls.input_counter}")
            return next_input
        try:
            idx, msg = next(cls.enumerator)
            if idx % 2 == 0:
                cls.consumed_messages.add(msg)
                log.debug(f"Yield msg_id {msg.msg_type}")
                return msg.msg_type
            else:
                log.debug(f"Yield msg_data {msg.msg_data}")
                return msg.msg_data
        except StopIteration:
            # This should actually never happen as the number of combinations is calculated based
            # the number of unconstrained inputs consumed by this component in an earlier phase.
            raise StopIteration(f"{cls.component.name} requested more inputs than available...")

    @classmethod
    def get_consumed_messages(cls) -> set[Message]:
        """
        Return the consumed messages.
        :return:
        """
        return cls.consumed_messages


    @classmethod
    def generate_input_combinations(cls, allow_repetition=False, length=None, warn_threshold=100):
        """
        Lazily generates all possible permutations of the inputs.

        Args:
            allow_repetition: Whether to allow selecting the same input multiple times (default: False)
            length: Length of permutations to generate (default: len(inputs))
            warn_threshold: Number of combinations above which to log.debug a warning

        Yields:
            Lists representing permutations of the inputs

        Raises:
            ValueError: If length > len(inputs) and allow_repetition=False
        """
        log.debug("Generating permutations with:")
        inputs = CANBus.read_all_msgs_of_types(cls.component.consumed_ids)

        for msg in inputs:
            log.debug(f"  {msg}")

        n = len(inputs)
        k = length//2 if length is not None else n

        # Validate
        if not allow_repetition and k > n:
            raise ValueError(f"Cannot generate permutations of length {k} from {n} inputs without repetition.")

        # Calculate total combinations
        if allow_repetition:
            total_combinations = n ** k
        else:
            total_combinations = factorial(n) // factorial(n - k)

        log.info(f"Generated {total_combinations} input combinations of length {length} to analyze")

        if total_combinations > warn_threshold:
            log.warning(f"Large number of input combinations to check: {total_combinations:,} combinations!")

        # Generate permutations
        if allow_repetition:
            # Use product for permutations with repetition
            yield from product(inputs, repeat=k)
        else:
            # Use permutations for permutations without repetition
            yield from permutations(inputs, k)

