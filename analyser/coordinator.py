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
            analyser_dict = {} # cache analysers so that if we have to rerun a component we don't have to rebuild the cfg
            for component in bus.components:
                if component.is_virtual:
                    continue

                mcsa = analyser_dict.get(component.name, MCSAnalyser(component)) # Runs in unconstrained mode because the Components have expected input = 0
                mcsa.analyse()

            for component in bus.components:
                if component.is_virtual or not component.subscriptions:
                    component.is_analysed = True


            while True:
                done = True
                for component in bus.components:
                    if not component.is_analysed:
                        done = False
                        if cls._can_analyse(component, bus):
                            mcsa = analyser_dict.get(component.name, MCSAnalyser(component))
                            mcsa.analyse()
                            component.is_analysed = True
                if done:
                    break
            cls._visualize(bus)

            print(f"Done! See http://{cls.vc.host}:{cls.vc.port} for results")


    @classmethod
    def _can_analyse(cls, c, bus) -> bool:
        can_provide = {}
        for msg_type, count in bus.msg_types_in_buffer.items():
            can_provide[Config.message_name_lookup.get(msg_type, str(msg_type))] = count
        does_expect = []
        for subscription in c.subscriptions:
            does_expect.append(Config.message_name_lookup.get(subscription, str(subscription)))
        log.info(f"Checking if {[c.name]} can be analysed...")
        log.info(f"it reads {c.subscriptions} and expects {c.max_expected_inputs} inputs max.")
        log.info(f"  {[c.name]} expects types {does_expect} for a total of max {c.max_expected_inputs} inputs.")
        log.info(f"  bus can provide {can_provide}")

        if not all(key in can_provide for key in does_expect):
            log.info(f"Buffer can't provide all message types.")
            return False
        if c.max_expected_inputs > bus.number_of_msgs_of_types(c.subscriptions):
            log.info(f"Buffer can't provide enough messages.")
            return False
        log.info(f"Good to go!")
        return True



    @classmethod
    def _visualize(cls, bus):

        for node, cid in bus.graph.nodes(data='cid'):
            c = bus.components[cid]
            if c.is_virtual:
                bus.graph.nodes[node]['type'] = 'virtual component'
                bus.graph.nodes[node]['color'] = '#CCCCCC'
            elif len(c.subscriptions) == 0:
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
            print(u, v, k, d)
            bus.graph.edges[u,v,k]['color'] = type_color_map.get(d, '#CCCCCC')

        cls.vc.send_graph(
            bus.graph,
            title="MCS Data Flow",
        )
