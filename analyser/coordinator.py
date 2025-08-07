from pathlib import Path

from analyser.can_simulator import CANBus
from analyser.component_analyser import ComponentAnalyser
from analyser.common import Config, logger
from analyser.mcs_graph import MCSGraph

log = logger(__name__)

class Coordinator:
    """
    The Coordinator marks the entry point of the 'Multi Component Analyser' and coordinates all analysing steps taken.

    The multi-component analysis works in multiple phases:

    Phase I:
    Retrieve information about the participants in the canbus system.
    - What message types (ids) are available?
    - Which component produces and consumes which messages?

    Phase II:
    Based on the information retrieved, try to analyse the components in such an order so that all messages types a
    component might consume are available on the bus. If a component produces a message type, components that consume
    this type that have already been analysed need to be re-analysed. This continues until all components are analysed.

    Phase III:
    Build a graph using the produced consumed information of the individual components.
    This phase is actually done simultaneously during Phase II.
    """

    graph: MCSGraph = MCSGraph()

    @classmethod
    def run(cls, config_path: Path = None, step_mode: bool = False):
        """
        Run the simulation
        :return:
        """
        if config_path:
            CANBus.init(config_path)

        with CANBus() as bus:
            # cache analysers so that if we have to rerun a component we don't have to rebuild the cfg
            analyser_dict = {}

            for component in bus.components:
                # Runs in unconstrained mode because the Components have expected input = 0
                mcsa = ComponentAnalyser(component)
                analyser_dict[component.name] = mcsa
                mcsa.analyse()
                if step_mode:
                    MCSGraph.visualize(bus, step_mode)

            # Mark leaf components as "analysed" no need to analyse them twice with unconstrained input.
            for component in bus.components:
                if not component.consumed_ids:
                    component.is_analysed = True

            # Try to find components that can be analysed given the messages on the bus.
            while True:
                made_progress = False
                for component in bus.components:
                    if not component.is_analysed and cls._can_analyse(component, bus):
                        made_progress = True
                        mcsa = analyser_dict.get(component.name)
                        mcsa.analyse()
                        component.is_analysed = True
                        if step_mode:
                            MCSGraph.visualize(bus, step_mode)
                if not made_progress:
                    break

            MCSGraph.visualize(step_mode=False, tracing=True)
            print(f"Done!")


    @classmethod
    def _can_analyse(cls, c, bus) -> bool:
        """
        Determine if a component is ready to be analysed.
        :param c:
        :param bus:
        :return:
        """
        can_provide = []
        for msg_type, count in bus.msg_types_in_buffer.items():
            can_provide.append(Config.message_name_lookup.get(msg_type, str(msg_type)))
        does_expect = []
        for subscription in c.consumed_ids:
            does_expect.append(Config.message_name_lookup.get(subscription, str(subscription)))
        """
        if not all(key in can_provide for key in does_expect):
            log.info(f"Buffer can't provide all message types.")
            return False
        """
        if c.max_expected_inputs // 2 > bus.number_of_msgs_of_types(c.consumed_ids):
            log.info(f"Not ready to analyse as not enough messages of the subscribed types are available.")
            log.info(f"{[c.name]} expects types {does_expect} for a total of max {c.max_expected_inputs} inputs.")
            log.info(f"bus can provide {can_provide}")
            return False
        return True
