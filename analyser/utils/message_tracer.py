from analyser.utils.logger import logger
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

        def get_paths_to(target_id: int) -> list[list[int]]:
            """Recursively build paths to target_id"""
            # get all possible ways how this message was produced.
            producers = cls._producers_of.get(target_id, [])

            if not producers:
                # This is a source message - return a path with just itself
                return [[target_id]]

            all_paths = []

            # Each producer represents one way to create this message (OR relationship)
            for prod in producers:
                if not prod['consumed_msg_ids']:
                    # No inputs but has a producer (shouldn't normally happen)
                    all_paths.append([target_id])
                elif len(prod['consumed_msg_ids']) == 1:
                    # Single input - extend each path from that input
                    input_id = prod['consumed_msg_ids'][0]
                    input_paths = get_paths_to(input_id)
                    for path in input_paths:
                        # Add current message to the end of each input path
                        all_paths.append(path + [target_id])
                else:
                    # Multiple inputs (AND relationship) - combine all inputs
                    # First, collect all unique source messages from all inputs
                    all_sources = set()
                    for input_id in prod['consumed_msg_ids']:
                        input_paths = get_paths_to(input_id)
                        for path in input_paths:
                            # Add all messages except the input itself (to avoid duplicates)
                            all_sources.update(path[:-1])

                    # Create a single path with all sources, then the inputs, then target
                    combined_path = sorted(list(all_sources))  # Sort for consistent ordering
                    combined_path.extend(prod['consumed_msg_ids'])  # Add the immediate inputs
                    combined_path.append(target_id)  # Add the target

                    # Remove duplicates while preserving order
                    seen = set()
                    deduped_path = []
                    for msg in combined_path:
                        if msg not in seen:
                            seen.add(msg)
                            deduped_path.append(msg)

                    all_paths.append(deduped_path)

            return all_paths

        return get_paths_to(msg_id)

    @classmethod
    def get_all_traces(cls, msg_ids: set[int]) -> dict[int, list[list[int]]]:
        """Get traces for all messages as a dictionary mapping msg_id to paths"""
        all_traces = {}

        # Build traces for each message
        for msg_id in sorted(msg_ids):
            all_traces[msg_id] = cls.get_full_trace(msg_id)

        return all_traces

    @classmethod
    def print_trace(cls, msg_id: int):
        """Print a simple trace for a message"""
        paths = cls.get_full_trace(msg_id)

        print(f"\nTrace for msg_id {msg_id}:")
        for path in paths:
            print(f"\t{path}")