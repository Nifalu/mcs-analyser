from analyser.io_state import IOState

class Message:
    def __init__(self, source: int, destination: int, msg_data: IOState):
        self.source = source
        self.dest = destination
        self.msg_data: IOState = msg_data

    def __repr__(self):
        return f"Message({self.source} -> {self.dest}) BV: {self.msg_data.bv}, constraints: {self.msg_data.constraints}"

    def __str__(self):
        return f"Message({self.source} -> {self.dest}) BV: {self.msg_data.bv}, constraints: {self.msg_data.constraints}"
