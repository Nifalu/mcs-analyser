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
        "source component": "#20BAA6",
        "component": "#596BE2",
        "sink component": "#59AFE2",
        # Edges
        "symbolic": "#596BE2",
        "concrete": "#2034BA",
        "given unconstrained input": "#20BAA6",
        "unconstrained": "#EC7D46"
    }
    node_labels = ['type', 'path', 'name']
    edge_labels = ['type', 'source', 'target', 'bv', 'value', 'constraints']

    @classmethod
    def run(cls, config_path: Path = None):
        """
        Run the simulation
        :return:
        """

        """
        Phase 1:
        Retrieve information about the participants in the canbus system.
        - What message types (ids) are available? -> retrieved during Canbus initialization.]
        - Who produces and consumes which messages? 
        """
        if config_path:
            CANBus.init(config_path)

        with CANBus() as bus:
            for component in bus.components.values():
                if component.is_virtual:
                    continue

                subscriptions: list[int] = MCSAnalyser.extract_symbols(component.path)

                mcsa = MCSAnalyser(component)
                mcsa.analyse()

                consumed_sources = mcsa.consumed_sources

                bus.write(component, consumed_msg)



                MCSAnalyser(component, run_with_unconstrained_inputs=True, count_inputs=True)
                cls._visualize(bus.graph)

            # Color all edges from this unconstrained run in red
            nx.set_edge_attributes(bus.graph, "given unconstrained input", "type")

            leaf_nodes = set()
            for node, component in bus.graph.nodes.data('component'):
                if bus.graph.in_degree(node) == 0:
                    leaf_nodes.add(node)
                    bus.graph.nodes[node]['type'] = 'source component'
                    bus.graph.nodes[node]['description'] = 'Component reads arbitrary (unconstrained) input'
                elif bus.graph.out_degree(node) == 0:
                    bus.graph.nodes[node]['type'] = 'sink component'
                    bus.graph.nodes[node]['description'] = 'Virtual component that collects the "final" outputs of other components'
                else:
                    bus.graph.nodes[node]['type'] = 'component'
                    bus.graph.nodes[node]['description'] = 'Component that computes some output(s) given an input(s)'

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

            cls._visualize(bus.graph)

        print(f"Done! See http://{cls.vc.host}:{cls.vc.port} for results")

    @classmethod
    def _visualize(cls, graph):
        cls.vc.send_graph(
            graph,
            title="MCS Data Flow",
            node_labels=cls.node_labels,
            edge_labels=cls.edge_labels,
            type_color_map=cls.type_color_map
        )
        input()
