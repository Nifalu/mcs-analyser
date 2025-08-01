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
    def get_full_trace(cls, msg_id: int) -> list[list[tuple[int, str | None, list[int]]]]:
        """
        Get all paths with edge information.
        Returns list of paths where each element is (msg_id, producer_component, [consumed_msg_ids])
        """

        def get_paths_to(target_id: int) -> list[list[tuple[int, str | None, list[int]]]]:
            """Recursively build paths to target_id with edge info"""
            producers = cls._producers_of.get(target_id, [])

            if not producers:
                # Source message - no inputs consumed
                return [[(target_id, None, [])]]

            all_paths = []

            for prod in producers:
                producer_component = prod['component']
                consumed_ids = prod['consumed_msg_ids']

                if not consumed_ids:
                    # No inputs but has a producer (source component)
                    all_paths.append([(target_id, producer_component, [])])
                elif len(consumed_ids) == 1:
                    # Single input
                    input_id = consumed_ids[0]
                    input_paths = get_paths_to(input_id)
                    for path in input_paths:
                        # Add current message with what it consumed
                        all_paths.append(path + [(target_id, producer_component, consumed_ids)])
                else:
                    # Multiple inputs - need to get all paths for all inputs
                    all_input_paths = []
                    for input_id in consumed_ids:
                        all_input_paths.extend(get_paths_to(input_id))

                    # Combine unique entries from all input paths
                    combined = []
                    seen = set()
                    for path in all_input_paths:
                        for entry in path:
                            key = (entry[0], entry[1])  # (msg_id, component)
                            if key not in seen:
                                seen.add(key)
                                combined.append(entry)

                    # Add current message
                    combined.append((target_id, producer_component, consumed_ids))
                    all_paths.append(combined)

            return all_paths

        return get_paths_to(msg_id)

    @classmethod
    def get_traces_dict(cls, keys: list[int]) -> dict[str, list[list[tuple]]]:
        """Get traces with edge information for visualization"""
        traces = {}
        for msg_id in keys:
            paths = cls.get_full_trace(msg_id)
            if paths:
                # Convert to JSON-serializable format
                traces[str(msg_id)] = [
                    [[msg_id, component, consumed_ids] for msg_id, component, consumed_ids in path]
                    for path in paths
                ]
        return traces

    @classmethod
    def print_trace(cls, msg_id: int):
        """Print a simple trace for a message"""
        paths = cls.get_full_trace(msg_id)

        print(f"\nTrace for msg_id {msg_id}:")
        for path in paths:
            print(f"\t{path}")