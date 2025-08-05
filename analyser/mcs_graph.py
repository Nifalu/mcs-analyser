from networkx import MultiDiGraph
from distinctipy import get_colors
from colorsys import rgb_to_hls, hls_to_rgb

from analyser.common import logger, MessageTracer, Config
from schnauzer import VisualizationClient
log = logger(__name__)


class MCSGraph(MultiDiGraph):
    """
    A specialized MultiDiGraph for representing CAN bus communication.
    Singleton pattern with reset capability.
    """
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MCSGraph, cls).__new__(cls)
            cls._instance.vc = VisualizationClient()
            cls._instance.type_color_map = None
        return cls._instance

    def __init__(self):
        # Only initialize the parent class once
        if not MCSGraph._initialized:
            super().__init__()
            MCSGraph._initialized = True

    @classmethod
    def get_instance(cls) -> 'MCSGraph':
        """Get or create the singleton instance"""
        return cls()

    @classmethod
    def reset(cls):
        """Reset the graph while keeping the same instance"""
        if cls._instance is not None:
            cls._instance.clear()  # MultiDiGraph's clear method
            # Don't reset type_color_map - it can be reused
            # Don't reset vc - keep the connection
            log.debug("MCSGraph reset")

    @classmethod
    def add_component(cls, name: str, cid: int, description: str):
        """Add a component node to the graph"""
        instance = cls.get_instance()
        instance.add_node(name, cid=cid, description=description)
        log.debug(f"Added component node: {name}")

    @classmethod
    def add_message_edge(cls, source: str, target: str, message_data: dict) -> bool:
        """Add a message edge between components"""
        instance = cls.get_instance()

        # Check if this exact message already exists
        edge_dict = instance.get_edge_data(source, target)
        if edge_dict:
            for key, edge in edge_dict.items():
                if message_data.get('msg_id') == edge.get('msg_id'):
                    log.debug(f"Message from ({[source]}->{[target]}) already in graph")
                    return False

        # Add the edge with all message data
        instance.add_edge(source, target, **message_data)
        msg_type = message_data.get('type', 'unknown')
        log.debug(f"Added edge {[source]} -> {[target]} with type {[msg_type]}")
        return True

    @staticmethod
    def _build_type_color_map() -> dict[str, str]:
        """Build color map for message types"""
        # Your existing implementation
        msg_type_strs = Config.message_name_lookup.values()

        exclude_colors = [
            (1, 0, 0), (0.9, 0, 0), (0.8, 0, 0), (1, 0.1, 0.1),  # reds
        ]

        colors_rgb = get_colors(len(msg_type_strs) + 10, exclude_colors=exclude_colors)

        pastel_colors = []
        for r, g, b in colors_rgb:
            h, l, s = rgb_to_hls(r, g, b)
            s = s * 0.80
            l = 0.4 + (l * 0.3)
            r, g, b = hls_to_rgb(h, l, s)

            if max(r, g, b) - min(r, g, b) > 0.1:
                pastel_colors.append((r, g, b))

        pastel_colors = pastel_colors[:len(msg_type_strs)]
        colors = ['#%02x%02x%02x' % tuple(int(c*255) for c in color) for color in pastel_colors]

        return dict(zip(msg_type_strs, colors))

    @classmethod
    def visualize(cls, step_mode=False, tracing=True):
        """Visualize the graph"""

        from analyser.can_simulator import CANBus # Avoiding circular imports

        instance = cls.get_instance()

        # Build color map if needed
        if instance.type_color_map is None:
            instance.type_color_map = instance._build_type_color_map()

        traces = None
        if tracing:
            traces = MessageTracer.get_traces_dict(CANBus.buffer.keys())
        # Color nodes based on type
        for node, cid in instance.nodes(data='cid'):
            c = CANBus.components[cid]
            if len(c.consumed_ids) == 0:
                instance.nodes[node]['type'] = 'source component'
                instance.nodes[node]['color'] = '#20BAA6'
            elif len(c.produced_ids) == 0:
                instance.nodes[node]['type'] = 'sink component'
                instance.nodes[node]['color'] = '#59AFE2'
            else:
                instance.nodes[node]['type'] = 'component'
                instance.nodes[node]['color'] = '#596BE2'

        # Color edges based on message type
        for u, v, k, d in instance.edges(keys=True, data='type'):
            color = instance.type_color_map.get(d, '#CCCCCC')
            instance.edges[u, v, k]['color'] = color

        instance.vc.send_graph(
            instance,
            title="MCS Data Flow",
            traces=traces
        )

        if step_mode:
            input("\nPress Enter to continue...\n")