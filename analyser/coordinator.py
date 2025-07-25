from schnauzer import VisualizationClient
from analyser.can_simulator import CANBus
from analyser.config import \
    Config
from analyser.mcs_analyser import MCSAnalyser
from pathlib import Path
from utils.logger import logger
log = logger(__name__)

class Coordinator:

    vc = VisualizationClient()

    @classmethod
    def run(cls, config_path: Path = None, step_mode: bool = False):
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
            analyser_dict = {} # cache analysers so that if we have to rerun a component we don't have to rebuild the cfg
            for component in bus.components:

                mcsa = analyser_dict.get(component.name, MCSAnalyser(component)) # Runs in unconstrained mode because the Components have expected input = 0
                mcsa.analyse()
                cls._visualize(bus, step_mode)

            for component in bus.components:
                if not component.subscriptions:
                    component.is_analysed = True

            while True:
                made_progress = False
                for component in bus.components:
                    if not component.is_analysed:
                        if cls._can_analyse(component, bus):
                            made_progress = True
                            mcsa = analyser_dict.get(component.name, MCSAnalyser(component))
                            mcsa.analyse()
                            component.is_analysed = True
                            cls._visualize(bus, step_mode)
                if not made_progress:
                    break

            step_mode = not step_mode
            cls._visualize(bus, step_mode)
            print(f"Done! See http://{cls.vc.host}:{cls.vc.port} for results")


    @classmethod
    def _can_analyse(cls, c, bus) -> bool:
        can_provide = []
        for msg_type, count in bus.msg_types_in_buffer.items():
            can_provide.append(Config.message_name_lookup.get(msg_type, str(msg_type)))
        does_expect = []
        for subscription in c.subscriptions:
            does_expect.append(Config.message_name_lookup.get(subscription, str(subscription)))
        """
        if not all(key in can_provide for key in does_expect):
            log.info(f"Buffer can't provide all message types.")
            return False
        """
        if c.max_expected_inputs // 2 > bus.number_of_msgs_of_types(c.subscriptions):
            log.info(f"Not ready to analyse as not enough messages of the subscribed types are available.")
            log.info(f"{[c.name]} expects types {does_expect} for a total of max {c.max_expected_inputs} inputs.")
            log.info(f"bus can provide {can_provide}")
            return False
        return True

    @classmethod
    def _visualize(cls, bus, step_mode=False):
        if not step_mode:
            return
        for node, cid in bus.graph.nodes(data='cid'):
            c = bus.components[cid]
            if len(c.subscriptions) == 0:
                bus.graph.nodes[node]['type'] = 'source component'
                bus.graph.nodes[node]['color'] = '#20BAA6'
            elif len(c.produced_msg_ids) == 0:
                bus.graph.nodes[node]['type'] = 'sink component'
                bus.graph.nodes[node]['color'] = '#59AFE2'
            else:
                bus.graph.nodes[node]['type'] = 'component'
                bus.graph.nodes[node]['color'] = '#596BE2'

        # Retrieve available message types
        msg_type_strs = set()
        for msg_type in bus.msg_types_in_buffer.keys():
            msg_type_strs.add(Config.message_name_lookup.get(msg_type, str(msg_type)))

        # Assign colors to message types
        type_color_map = dict()
        colors = ["#1f77b4", "#2ca02c", "#9467bd", "#8c564b", "#17becf", "#bcbd22", "#7f7f7f"]
        for i, msg_type_str in enumerate(msg_type_strs):
            color = colors[i % len(colors)]
            type_color_map[msg_type_str] = color

        for u, v, k, d in bus.graph.edges(keys=True, data='type'):
            bus.graph.edges[u,v,k]['color'] = type_color_map.get(d, '#CCCCCC')

        cls.vc.send_graph(
            bus.graph,
            title="MCS Data Flow",
        )
        if step_mode:
            input("\nPress Enter to continue...\n")
