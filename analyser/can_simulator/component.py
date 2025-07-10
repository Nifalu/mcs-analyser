from pathlib import Path

class Component:
    def __init__(self, name: str, path: Path, cid: int):
        self.name = name
        self.path = path
        self.cid = cid
        self.expected_inputs = 0

    def __repr__(self):
        return f'Component({self.name}, id: {self.cid}, path: {self.path})'

    def __str__(self):
        return f'Component({self.name}, id: {self.cid}, path: {self.path})'