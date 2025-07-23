from pathlib import Path

class Component:
    def __init__(self, name: str, path: Path, cid: int, is_virtual: bool = False):
        self.name = name
        self.path = path
        self.cid = cid
        self.max_expected_inputs = 0
        self.is_virtual = is_virtual

        self.subscriptions: set[int] = set()

    def update_max_expected_inputs(self, number_of_inputs: int):
        if number_of_inputs > self.max_expected_inputs:
            self.max_expected_inputs = number_of_inputs

    def reset_max_expected_inputs(self):
        self.max_expected_inputs = 0

    def __repr__(self):
        return f'Component({self.name}, id: {self.cid}, path: {self.path})'

    def __str__(self):
        return f'Component({self.name}, id: {self.cid}, path: {self.path})'