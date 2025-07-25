from pathlib import Path

from analyser.config import \
    Config
from utils.logger import logger
log = logger(__name__)

class Component:
    def __init__(self, name: str, path: Path):
        self.name = name
        self.path = path
        self.max_expected_inputs = 0
        self.is_analysed = False

        self.subscriptions: set[int] = set()
        self.produced_msg_ids: set[int] = set()

    def update_max_expected_inputs(self, number_of_inputs: int):
        if number_of_inputs > self.max_expected_inputs:
            self.max_expected_inputs = number_of_inputs

    def reset_max_expected_inputs(self):
        self.max_expected_inputs = 0

    def add_subscription(self, subscription):
        if subscription not in self.subscriptions:
            subscription_str = Config.message_name_lookup.get(subscription, str(subscription))
            log.info(f"{self} can read messages of type {[subscription_str]} (0x{subscription:x})")
            self.subscriptions.add(subscription)

    def add_produced_msg_id(self, msg_id):
        if msg_id not in self.produced_msg_ids:
            produced_msg_type_str = Config.message_name_lookup.get(msg_id, str(msg_id))
            log.info(f"{self} can produce messages of type {[produced_msg_type_str]} (0x{msg_id:x}) messages")
            self.produced_msg_ids.add(msg_id)

    def __repr__(self):
        return f'{[self.name]}'

    def __str__(self):
        return f'{[self.name]}'