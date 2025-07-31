from analyser.utils import Config, logger
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from analyser.io import IOState

log = logger(__name__)

class Message:
    def __init__(self,producer_component_name: str, msg_id: 'IOState', msg_data: 'IOState'):
        if msg_id.is_symbolic():
            log.warning(f"{producer_component_name} produced a message of symbolic type")
            self.msg_type_str = "symbolic"
        else:
            self.msg_type_str = Config.message_name_lookup.get(msg_id.bv.concrete_value, str(msg_id.bv.concrete_value))
        self.producer_component_name: str = producer_component_name
        self.msg_type: 'IOState' = msg_id
        self.msg_data: 'IOState' = msg_data

    def __hash__(self):
        return hash((self.producer_component_name, self.msg_type, self.msg_data))

    def __eq__(self, other):
        if not isinstance(other, Message):
            return False
        return (self.producer_component_name == other.producer_component_name and
                self.msg_type == other.msg_type and
                self.msg_data == other.msg_data)

    def __repr__(self):
        return f"{[self.msg_type_str]}"

    def __str__(self):
        return f"{[self.msg_type_str]}"