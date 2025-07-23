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

                mcsa = MCSAnalyser(component) # Runs in unconstrained mode because the Components have expected input = 0
                mcsa.analyse()

                # msg ID's (integer) this component reads. If the subscription list is empty, the component is probably a leaf
                subscriptions = component.subscriptions
                # msg ID's (as IOState) this component produces (the msg id's should be concrete but we allow symbolic to catch those cases.
                produces = mcsa.produced_msg_ids

            cls._analyze_in_dependency_order(bus)

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

    # In analyser/coordinator.py
    @classmethod
    def _analyze_in_dependency_order(cls, bus: CANBus):
        """Analyze components in order based on their dependencies"""
        analyzed = set()
        message_buffer = []  # List of available messages

        # Start with sensors (empty subscriptions)
        for c in bus.components.values():
            if c.is_virtual or not c.subscriptions:
                analyzed.add(c)

        log.info(f"\n=== Phase 2: Dependency-based analysis ===")
        log.info(f"Found {len(analyzed)} sensor components")

        input(" == Works up to here == ")

        # Now analyze components whose dependencies are satisfied
        while len(analyzed) < len([c for c in bus.components.values() if not c.is_virtual]):
            made_progress = False

            for component in bus.components.values():
                if component.is_virtual or component.cid in analyzed:
                    continue

                # Check if we can analyze this component
                if cls._can_analyze(component, message_buffer):
                    log.info(f"\nAnalyzing component: {component.name}")

                    # Get relevant input combinations
                    input_combinations = cls._get_input_combinations(component, message_buffer)

                    # Analyze with each combination
                    for combination in input_combinations:
                        messages = cls._analyze_with_inputs(component, combination)
                        message_buffer.extend(messages)

                    analyzed.add(component.cid)
                    made_progress = True

            if not made_progress:
                # No component can be analyzed - might have circular dependencies
                remaining = [c.name for c in bus.components.values()
                            if not c.is_virtual and c.cid not in analyzed]
                log.warning(f"Cannot analyze remaining components: {remaining}")
                break


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
