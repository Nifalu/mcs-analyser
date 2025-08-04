from networkx import MultiDiGraph
from analyser.common import logger
log = logger(__name__)


class CANGraph(MultiDiGraph):
    """
    A specialized MultiDiGraph for representing CAN bus communication.
    Handles component nodes and message edges.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def add_component(self, name: str, cid: int, description: str):
        """Add a component node to the graph"""
        self.add_node(name, cid=cid, description=description)
        log.debug(f"Added component node: {name}")

    def add_message_edge(self, source: str, target: str, message_data: dict) -> bool:
        """
        Add a message edge between components.

        Returns:
            bool: True if edge was added, False if it already exists
        """
        # Check if this exact message already exists
        edge_dict = self.get_edge_data(source, target)
        if edge_dict:
            for key, edge in edge_dict.items():
                if message_data.get('msg_id') == edge.get('msg_id'):
                    log.debug(f"Message from ({[source]}->{[target]}) is already in the graph")
                    return False

        # Add the edge with all message data
        self.add_edge(source, target, **message_data)
        log.debug(f"Added edge between {[source]} -> {[target]} with message of type {[message_data.get('type', 'unknown')]}")
        return True