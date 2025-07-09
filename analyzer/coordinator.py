import \
    networkx as nx
from schnauzer import VisualizationClient
from analyzer.CANSim import CANBus
from analyzer.MCSAnalyser import MCSAnalyser
from pathlib import Path
from utils.logger import logger
log = logger(__name__)


class Coordinator:

    vc = VisualizationClient()
    type_color_map = {
        # Nodes
        "input": "#9FE2BF",
        "output": "#CCCCFF",
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
            for component in bus.components:
                MCSAnalyser(component, run_with_unconstrained_inputs=True, count_inputs=True).analyse()

            # Color all edges from this unconstrained run in red
            nx.set_edge_attributes(bus.graph, "unconstrained", "type")

            leaf_nodes = {n for n in bus.graph.nodes() if bus.graph.in_degree(n) == 0}

            # Second iteration: Do the analysis
            for node in leaf_nodes:
                component = bus.graph.nodes[node]['component']
                MCSAnalyser(component, run_with_unconstrained_inputs=True).analyse()

            analyzed = list(leaf_nodes)
            analyzed.append(0)
            while len(analyzed) < len(bus.components) + 1:
                for node in bus.graph.nodes():
                    if node in analyzed:
                        continue
                    predecessors = set(bus.graph.predecessors(node))
                    if not predecessors.issubset(analyzed):
                        continue

                    component = bus.graph.nodes[node]['component']

                    MCSAnalyser(component).analyse()
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

