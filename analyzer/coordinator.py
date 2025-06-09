from analyzer.io_state import \
    IOConfig, \
    Component, \
    IOState, \
    IOSnapshot
from analyzer.simple_analyzer import SimpleAnalyzer
from pathlib import Path
from networkx import DiGraph



class Coordinator:

    def __init__(self,
                 config_path: Path = Path.cwd() / "config.json",
                 ):
        self.config = _parse(config_path)
        self.graph = DiGraph()

    def run(self):

        queue: list[IOSnapshot] = []

        for cid in self.config.leaf_components:
            arbitrary_input = IOState.unconstrained("input", 64)
            c = self.config.components[cid]
            sa = SimpleAnalyzer(c.path, [arbitrary_input], self.config)
            snapshot = sa.analyze()
            snapshot.add_input(0, arbitrary_input)
            snapshot.print_rich()
            queue.append(snapshot)

        while queue:
            origin_snapshot = queue.pop(0)
            for cid, values in origin_snapshot.outputs.items():
                if cid in self.config.leaf_components:
                    raise ValueError(f"Unexpected leaf component {cid} in queue. This should not happen.")
                if cid == 0:
                    continue # We have reached the root

                c = self.config.components[cid]
                sa = SimpleAnalyzer(c.path, values, self.config)
                new_snapshot = sa.analyze()
                for v in values:
                    new_snapshot.add_input(cid, v)
                new_snapshot.print_rich()
                queue.append(new_snapshot)





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
        c = Component(
            path=Path(components_dir, comp['filename']),
            id=int(comp['id']),
            is_leaf=comp.get('is_leaf', True),
            input_mapping=comp.get('input_mapping', {})
        )

        if c.is_leaf:
            config.leaf_components.add(c.id)

        config.components[c.id] = c

    return config