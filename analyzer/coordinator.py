from collections import \
    deque

from networkx.classes import \
    MultiDiGraph
from schnauzer import VisualizationClient

from analyzer import \
    io_state
from analyzer.CANSim import \
    CANBus, \
    Message
from analyzer.MCSAnalyser import MCSAnalyser
from pathlib import Path

from analyzer.io_state import \
    IOSnapshot, \
    IOState, \
    IOConfig
from analyzer.simple_analyzer import \
    SimpleAnalyzer
from utils.logger import logger
log = logger(__name__)


class Coordinator:

    def __init__(self,
                 config_path: Path = Path.cwd() / "config.json",
                 ):
        self.graph = None
        self.bus = CANBus(config_path)
        self.old_config = _parse(config_path)


    def run(self):
        """
        Run the simulation
        :return:
        """

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
        node_labels = ['type', 'path']
        edge_labels = ['type', 'source', 'target', 'bv', 'value', 'constraints']

        graph = self.bus.graph

        # Analyse all components with unconstrained input to get an initial graph
        # We also count the inputs here to reduce the possible input combinations.
        for component in self.bus.components:
            MCSAnalyser(component, run_with_unconstrained_inputs=True, count_inputs=True).analyse() # this automatically updates self.graph

        leaf_nodes = {n for n in graph.nodes() if graph.in_degree(n) == 0}
        unconstrained_graph = self.bus.graph.copy() # local reference for better readability

        # reset the graph
        self.bus.buffer = [] # clear messages on the bus
        self.bus.graph = MultiDiGraph()
        self.bus.graph.add_node(0)
        graph = self.bus.graph

        # analyze the leaf components first
        for node in leaf_nodes:
            component = unconstrained_graph.nodes[node]['component']
            MCSAnalyser(component, run_with_unconstrained_inputs=True).analyse()
            vc.send_graph(
                self.bus.graph,
                node_labels=node_labels,
                edge_labels=edge_labels,
                type_color_map=type_color_map
            )


        analyzed = list(leaf_nodes)
        analyzed.append(0)
        while len(analyzed) < len(self.bus.components) + 1:
            for node in graph.nodes():
                if node in analyzed:
                    continue
                predecessors = set(graph.predecessors(node))
                if not predecessors.issubset(analyzed):
                    continue

                component = unconstrained_graph.nodes[node]['component']
                print(f"Going to analyze {component} with {len(self.bus.read_all())} possible inputs")

                MCSAnalyser(component).analyse()
                vc.send_graph(
                    self.bus.graph,
                    node_labels=node_labels,
                    edge_labels=edge_labels,
                    type_color_map=type_color_map
                )
                analyzed.append(node)

        self.add_unconstrained_edges(unconstrained_graph, graph)
        vc.send_graph(
            self.bus.graph,
            node_labels=node_labels,
            edge_labels=edge_labels,
            type_color_map=type_color_map
        )


    def add_unconstrained_edges(self, uc_graph, c_graph):
        """
        Compare IOStates between unconstrained and constrained graphs.
        Prints IOStates that exist in uc_graph but not in c_graph.
        """
        missing_iostates = []

        # Iterate through all edges in unconstrained graph with keys
        for uc_source, uc_destination, uc_key, uc_data in uc_graph.edges(data=True, keys=True):

            uc_msg_data = uc_data.get('msg_data')
            if not uc_msg_data:
                continue

            log.info(f"We're looking at uc_source={uc_source} uc_destination={uc_destination} uc_key={uc_key}")

            # Check if this edge (with same source/dest) exists in constrained graph
            found_matching = False

            # Check if the nodes exist in the constrained graph
            if c_graph.has_node(uc_source) and c_graph.has_node(uc_destination):
                # Get all edges between these nodes in the constrained graph
                if c_graph.has_edge(uc_source, uc_destination):
                    log.info("located the edge(s)")
                    # Iterate through all edges between these nodes
                    for c_key, c_data in c_graph[uc_source][uc_destination].items():
                        log.info(f"At edge {c_key}")
                        c_msg_data = c_data.get('msg_data')
                        if c_msg_data and uc_msg_data.equals(c_msg_data):
                            found_matching = True
                            break

            if not found_matching:
                self.bus.graph.add_edge(
                    uc_source,
                    uc_destination,
                    type="unconstrained",
                    bv=str(uc_data['bv']),
                    constraints=uc_data['constraints'],
                    msg_data=uc_data['msg_data']
                )
                missing_iostates.append({
                    'source': uc_source,
                    'destination': uc_destination,
                    'key': uc_key,
                    'io_state': uc_msg_data
                })

        # Print results
        if missing_iostates:
            print(f"\nFound {len(missing_iostates)} IOStates in unconstrained graph that are not in constrained graph:")
            for item in missing_iostates:
                print(f"\nEdge: {item['source']} -> {item['destination']} (key: {item['key']})")
                print(f"Missing IOState: {item['io_state'].name}")
                if item['io_state'].is_symbolic():
                    print(f"Constraints: {item['io_state'].constraints}")
                else:
                    print(f"Concrete value: {item['io_state'].bv.concrete_value}")
        else:
            print("\nAll IOStates from unconstrained graph exist in constrained graph")

        return missing_iostates


    def run_simple(self):
        self.graph = MultiDiGraph()
        queue: list[IOSnapshot] = []

        for cid in self.old_config.leaf_components:
            arbitrary_input = IOState.unconstrained(f"input_{cid}", 64)
            c = self.old_config.components[cid]
            sa = SimpleAnalyzer(c.path, [arbitrary_input], self.old_config)
            snapshot = sa.analyze()
            snapshot.add_input(0, arbitrary_input)
            snapshot.print_rich()
            queue.append(snapshot)
            self.graph.add_node(f"input_{cid}", type="input")
            self.graph.add_node(snapshot.name, type="component")
            self.graph.add_edge(f"input_{cid}", snapshot.name, type="symbolic")

        while queue:
            origin_snapshot = queue.pop(0)
            for cid, values in origin_snapshot.outputs.items():
                if cid in self.old_config.leaf_components:
                    raise ValueError(f"Unexpected leaf component {cid} in queue. This should not happen.")
                if cid == 0:  # We have reached the root
                    self.graph.add_node(f"output_{cid}", type="output")
                    for v in values:
                        t = "symbolic" if v.is_symbolic else "concrete"
                        self.graph.add_edge(origin_snapshot.name, f"output_{cid}", type=t)
                    continue

                c = self.old_config.components[cid]
                sa = SimpleAnalyzer(c.path, values, self.old_config)
                new_snapshot = sa.analyze()
                self.graph.add_node(new_snapshot.name, type="component")
                for v in values:
                    new_snapshot.add_input(cid, v)
                    t = "symbolic" if v.is_symbolic else "concrete"
                    if v.is_symbolic:
                        self.graph.add_edge(origin_snapshot.name, new_snapshot.name, type=t, bv=str(v.bv), constraints=str(v.constraints))
                    else:
                        self.graph.add_edge(origin_snapshot.name, new_snapshot.name, type=t, bv=v.bv, value=v.bv.concrete_value)

                new_snapshot.print_rich()
                queue.append(new_snapshot)

        vc = VisualizationClient()
        type_color_map = {
            # Nodes
            "input": "#9FE2BF",
            "output": "#CCCCFF",
            "component": "#6495ED",
            # Edges
            "symbolic": "#FFBF00",
            "concrete": "#DE3163"
        }
        vc.send_graph(self.graph, type_color_map=type_color_map)



def _parse(path: Path) -> IOConfig:
    """
    Parse the configuration file to get the components and their mappings.
    """
    import json
    with open(path, 'r') as f:
        data = json.load(f)
    components_dir = Path(data['components_dir'])
    config = IOConfig({}, set())
    for comp in data['components']:
        c = io_state.Component(
            path=Path(components_dir, comp['filename']),
            id=int(comp['id']),
            is_leaf=comp.get('is_leaf', True),
            input_mapping=comp.get('input_mapping', {})
        )

        if c.is_leaf:
            config.leaf_components.add(c.id)

        config.components[c.id] = c

    return config