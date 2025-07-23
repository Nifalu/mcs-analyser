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
        - Who produces and consumes which messages? -> tracked in unconstrained mode
        """
        if config_path:
            CANBus.init(config_path)

        with CANBus() as bus:
            for component in bus.components:
                if component.is_virtual:
                    continue

                mcsa = MCSAnalyser(component) # Runs in unconstrained mode because the Components have expected input = 0
                mcsa.analyse()

            cls._visualize(bus.graph)


            analyser_dict = {} # cache analysers so that if we have to rerun a component we don't have to rebuild the cfg
            for component in bus.components:
                if component.is_virtual or not component.subscriptions:
                    component.is_analysed = True

            while True: # need to find a solution here:
                for component in bus.components:
                    if not component.is_analysed and cls._can_analyse(component, bus):
                        mcsa = MCSAnalyser(component) # Runs in normal mode
                        analyser_dict[component.name] = mcsa
                        mcsa.analyse()
                        component.is_analysed = True
                cls._visualize(bus.graph)

            print(f"Done! See http://{cls.vc.host}:{cls.vc.port} for results")


    @classmethod
    def _can_analyse(cls, c, bus) -> bool:
        log.info(f"Checking if {[c.name]} can be analysed...")
        log.info(f"it reads {c.subscriptions}")
        log.info(f"bus can provide {bus.msg_types_in_buffer}")
        for subscription in c.subscriptions:
            if subscription not in bus.msg_types_in_buffer:
                log.info(f"subscription {subscription} not in bus msg_types_in_buffer")
                return False
        if c.max_expected_inputs > len(bus.buffer):
            log.info(f"Buffer can't provide enough messages.")
            return False
        return True



    @classmethod
    def _visualize(cls, graph):
        cls.vc.send_graph(
            graph,
            title="MCS Data Flow",
            #node_labels=cls.node_labels,
            #edge_labels=cls.edge_labels,
            #type_color_map=cls.type_color_map
        )
        input("Visualisation break")
