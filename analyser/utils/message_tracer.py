from analyser.utils import logger
log = logger(__name__)

class MessageTracer:
    _producers_of: dict[int, list[dict]] = dict()
    _consumers_of: dict[int, list[dict]] = dict()
    _next_production_id: int = 0

    @classmethod
    def reset(cls):
        cls._producers_of.clear()
        cls._consumers_of.clear()
        cls._next_production_id = 0

    @classmethod
    def add_production(
            cls,
            produced_msg_id: int,
            consumed_msgs_ids: list[int],
            producer_name: str
    ) -> None:
        production = {
            'output_msg_id': produced_msg_id,
            'consumed_msg_ids': consumed_msgs_ids,
            'component': producer_name,
            'production_id': cls._next_production_id,
        }
        cls._next_production_id += 1

        # store this production as producer of produced_msg_id
        if produced_msg_id not in cls._producers_of:
            cls._producers_of[produced_msg_id] = []
        cls._producers_of[produced_msg_id].append(production)

        # store this production as consumer of the input msg ids.
        for consumed_msg_id in production['consumed_msg_ids']:
            if consumed_msg_id not in cls._consumers_of:
                cls._consumers_of[consumed_msg_id] = []
            cls._consumers_of[consumed_msg_id].append(production)
        log.debug(f"Recorded production #{production['production_id']}: {producer_name} produced msg {produced_msg_id} from inputs {production['consumed_msg_ids']}")

    @classmethod
    def get_full_trace(cls, msg_id: int) -> list[list[int]]:
        """Get all paths from source messages to this message as lists of msg_ids"""
        paths = []

        def trace_back(current_id: int, current_path: list[int]):
            # Add current message to path
            current_path = current_path + [current_id]

            # Get producers of this message
            producers = cls._producers_of.get(current_id, [])

            if not producers:
                # This is a source message - we've reached the beginning
                paths.append(current_path[::-1])  # Reverse to show source->destination
                return

            # For each way this message was produced
            for prod in producers:
                # Trace back through each input
                for input_id in prod['consumed_msg_ids']:
                    trace_back(input_id, current_path)

        trace_back(msg_id, [])
        return paths

    @classmethod
    def print_trace(cls, msg_id: int):
        """Print a simple trace for a message"""
        paths = cls.get_full_trace(msg_id)

        print(f"\nTrace for msg_id: {msg_id}:")
        for i, path in enumerate(paths):
            path_str = " → ".join(str(p) for p in path)
            print(f"  Path {i+1}: {path_str}")
