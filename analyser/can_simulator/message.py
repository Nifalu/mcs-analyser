from analyser.config import Config
from analyser.io_state import IOState

class Message:
    def __init__(self,source_cid: int, msg_id: IOState, msg_data: IOState):
        self.source_cid = source_cid
        self.msg_id: IOState = msg_id
        self.msg_data: IOState = msg_data

    def __hash__(self):
        return hash((self.source_cid, self.msg_id, self.msg_data))

    def __eq__(self, other):
        if not isinstance(other, Message):
            return False
        return (self.source_cid == other.source_cid and
                self.msg_id == other.msg_id and
                self.msg_data == other.msg_data)

    def __repr__(self):
        if self.msg_id.is_symbolic():
            return f"Message(SYMBOLIC TYPE) BV: {self.msg_data.bv}, constraints: {self.msg_data.constraints}"
        msg_name = Config.message_name_lookup.get(self.msg_id.bv.concrete_value, f"unknown-(id={self.msg_id.bv.concrete_value})")
        return f"Message({msg_name} BV: {self.msg_data.bv}, constraints: {self.msg_data.constraints}"

    def __str__(self):
        if self.msg_id.is_symbolic():
            return f"Message(SYMBOLIC TYPE) BV: {self.msg_data.bv}, constraints: {self.msg_data.constraints}"
        msg_name = Config.message_name_lookup.get(self.msg_id.bv.concrete_value, f"unknown-(id={self.msg_id.bv.concrete_value})")
        return f"Message({msg_name} BV: {self.msg_data.bv}, constraints: {self.msg_data.constraints}"


