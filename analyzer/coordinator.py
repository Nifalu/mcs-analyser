from schnauzer import VisualizationClient
from analyzer.CANSim import CANBus
from analyzer.MCSAnalyser import MCSAnalyser
from pathlib import Path
from utils.logger import logger
log = logger(__name__)


class Coordinator:

    def __init__(self,
                 config_path: Path = Path.cwd() / "config.json",
                 ):
        self.graph = None
        self.bus = CANBus(config_path)

    def run(self):

        for idx, component in enumerate(self.bus.components):
            self.bus.graph.add_node("Unconstrained Input")
            self.bus.graph.add_edge("Unconstrained Input", component.id)
            MCSAnalyser(component, True).analyse()

        """
        while queue:
            origin_snapshot = queue.pop(0)
            for cid, values in origin_snapshot.outputs.items():
                if cid in self.config.leaf_components:
                    raise ValueError(f"Unexpected leaf component {cid} in queue. This should not happen.")
                if cid == 0:  # We have reached the root
                    self.graph.add_node(f"output_{cid}", type="output")
                    for v in values:
                        t = "symbolic" if v.is_symbolic else "concrete"
                        self.graph.add_edge(origin_snapshot.name, f"output_{cid}", type=t)
                    continue

                c = self.config.components[cid]
                sa = SimpleAnalyzer(c.path, values, self.config)
                new_snapshot = sa.analyze()
                self.graph.add_node(new_snapshot.name, type="component")
                for v in values:
                    new_snapshot.add_input(cid, v)
                    t = "symbolic" if v.is_symbolic else "concrete"
                    self.graph.add_edge(origin_snapshot.name, new_snapshot.name, type=t)
                new_snapshot.print_rich()
                queue.append(new_snapshot)
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
        vc.send_graph(self.bus.graph, type_color_map=type_color_map)
