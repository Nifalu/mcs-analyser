from pathlib import Path
from distinctipy import get_colors
from colorsys import rgb_to_hls, hls_to_rgb

from schnauzer import VisualizationClient
from analyser.can_simulator import CANBus
from analyser.component_analyser import ComponentAnalyser
from analyser.utils import Config, MessageTracer, logger
log = logger(__name__)

class Coordinator:
    """
    The Coordinator marks the entry point of the 'Multi Component Analyser' and coordinates all analysing steps taken.

    """

    vc = VisualizationClient()
    type_color_map = None

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
        cls.type_color_map = cls._build_type_color_map()

        with CANBus() as bus:
            analyser_dict = {} # cache analysers so that if we have to rerun a component we don't have to rebuild the cfg
            for component in bus.components:

                mcsa = analyser_dict.get(component.name, ComponentAnalyser(component)) # Runs in unconstrained mode because the Components have expected input = 0
                mcsa.analyse()
                if step_mode:
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
                            mcsa = analyser_dict.get(component.name, ComponentAnalyser(component))
                            mcsa.analyse()
                            component.is_analysed = True
                            if step_mode:
                                cls._visualize(bus, step_mode)
                if not made_progress:
                    break

            for msg_id in bus.buffer.keys():
                MessageTracer.print_trace(msg_id)

            cls._visualize(bus, False)
            print(f"Done!")


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
    def _build_type_color_map(cls) -> dict[str, str]:
        # Retrieve available message types
        msg_type_strs = Config.message_name_lookup.values()

        # Exclude red, white, and grey colors
        exclude_colors = [
            (1, 0, 0), (0.9, 0, 0), (0.8, 0, 0), (1, 0.1, 0.1),  # reds
        ]

        # Generate more colors than needed to have options
        colors_rgb = get_colors(len(msg_type_strs) + 10, exclude_colors=exclude_colors)

        # Convert to pastel by adjusting saturation and lightness
        pastel_colors = []
        for r, g, b in colors_rgb:
            # Convert RGB to HSL
            h, l, s = rgb_to_hls(r, g, b)

            # Make more pastel:
            # - Reduce saturation (multiply by 0.6-0.7 for softer colors)
            # - Increase lightness (but not too much to avoid white)
            s = s * 0.80  # Reduce saturation for softer colors
            l = 0.4 + (l * 0.3)  # Push lightness toward 60-90% range

            # Convert back to RGB
            r, g, b = hls_to_rgb(h, l, s)

            # Skip if too grey (when r, g, b are too similar)
            if max(r, g, b) - min(r, g, b) > 0.1:  # Ensure some color variation
                pastel_colors.append((r, g, b))

        # Take only the needed number of colors
        pastel_colors = pastel_colors[:len(msg_type_strs)]

        # Convert RGB tuples to hex
        colors = ['#%02x%02x%02x' % tuple(int(c*255) for c in color) for color in pastel_colors]

        return dict(zip(msg_type_strs, colors))

    @classmethod
    def _visualize(cls, bus, step_mode=False):
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

        for u, v, k, d in bus.graph.edges(keys=True, data='type'):
            bus.graph.edges[u,v,k]['color'] = cls.type_color_map.get(d, '#CCCCCC')

        cls.vc.send_graph(
            bus.graph,
            title="MCS Data Flow",
        )

        if step_mode:
            input("\nPress Enter to continue...\n")
