from collections import \
    deque

from networkx.classes import \
    MultiDiGraph
from schnauzer import VisualizationClient

from analyzer import \
    io_state
from analyzer.CANSim import CANBus
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
            "concrete": "#DE3163"
        }
        node_labels = ['type', 'path']
        edge_labels = ['type', 'source', 'target', 'bv', 'value', 'constraints']

        initial_graph = self.bus.graph.copy() # local reference for better readability
        graph = self.bus.graph

        # Analyse all components with unconstrained input to get an initial graph
        # We also count the inputs here to reduce the possible input combinations.
        for component in self.bus.components:
            MCSAnalyser(component, run_with_unconstrained_inputs=True, count_inputs=True).analyse() # this automatically updates self.graph

        self.bus.buffer = [] # reset the buffer
        leaf_nodes = {n for n in graph.nodes() if graph.in_degree(n) == 0}

        self.bus.buffer = [] # clear messages on the bus

        # reset the graph
        self.bus.graph = MultiDiGraph()
        self.bus.graph.add_node(0)
        graph = self.bus.graph

        # analyze the leaf components first
        for node in leaf_nodes:
            component = initial_graph.nodes[node]['component']
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

                component = initial_graph.nodes[node]['component']
                print(f"Going to analyze {component} with {len(self.bus.read_all())} possible inputs")

                MCSAnalyser(component).analyse()
                vc.send_graph(
                    self.bus.graph,
                    node_labels=node_labels,
                    edge_labels=edge_labels,
                    type_color_map=type_color_map
                )
                analyzed.append(node)




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