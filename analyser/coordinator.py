import networkx as nx
from schnauzer import VisualizationClient
from analyser.can_simulator import CANBus
from analyser.mcs_analyser import MCSAnalyser
from pathlib import Path
from utils.logger import logger
log = logger(__name__)

class Coordinator:

    vc = VisualizationClient()
    type_color_map = {
        # Nodes
        "source component": "#9FE2BF",
        "sink component": "#CCCCFF",
        "component": "#6495ED",
        # Edges
        "symbolic": "#FFBF00",
        "concrete": "#DE3163",
        "unconstrained": "#FF0000"
    }
    node_labels = ['type', 'path', 'name']
    edge_labels = ['type', 'source', 'target', 'bv', 'value', 'constraints']

    @classmethod
    def run(cls, config_path: Path = None):
        """
        Run the simulation
        :return:
        """

        if config_path:
            CANBus.init(config_path)

        with CANBus() as bus:

            # First iteration: Retrieve Data Flow Information
            for component in bus.components.values():
                MCSAnalyser(component, run_with_unconstrained_inputs=True, count_inputs=True)

            # Color all edges from this unconstrained run in red
            nx.set_edge_attributes(bus.graph, "unconstrained", "type")

            leaf_nodes = set()
            for node, component in bus.graph.nodes.data('component'):
                if bus.graph.in_degree(node) == 0:
                    leaf_nodes.add(node)
                    bus.graph.nodes[node]['type'] = 'source component'
                elif bus.graph.out_degree(node) == 0:
                    bus.graph.nodes[node]['type'] = 'sink component'
                else:
                    bus.graph.nodes[node]['type'] = 'component'


            # Second iteration: Do the analysis
            for node in leaf_nodes:
                component = bus.graph.nodes[node]['component']
                MCSAnalyser(component, run_with_unconstrained_inputs=True)

            analyzed = list(leaf_nodes)
            analyzed.append(0)
            while len(analyzed) < len(bus.components.values()) + 1:
                for node in bus.graph.nodes():
                    if node in analyzed:
                        continue
                    predecessors = set(bus.graph.predecessors(node))
                    if not predecessors.issubset(analyzed):
                        continue

                    component = bus.graph.nodes[node]['component']

                    MCSAnalyser(component)
                    analyzed.append(node)

            cls._visualize(bus.graph)

        print(f"Done! See http://{cls.vc.host}:{cls.vc.port} for results")

    @classmethod
    def _visualize(cls, graph):
        cls.vc.send_graph(
            graph,
            node_labels=cls.node_labels,
            edge_labels=cls.edge_labels,
            type_color_map=cls.type_color_map
        )
