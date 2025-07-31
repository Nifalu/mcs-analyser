class Config:
    default_var_length: int = 0
    input_hooks: list[str] = []
    output_hooks: list[str] = []
    message_name_lookup: dict[int, str] = {}
    _initialized = False

    @classmethod
    def init(cls, default_var_length: int = 0, input_hooks: list[str] = None, output_hooks: list[str] = None, message_name_lookup: dict[int, str] = None):
        cls.default_var_length = default_var_length
        cls.input_hooks = input_hooks or []
        cls.output_hooks = output_hooks or []
        cls.message_name_lookup = message_name_lookup or dict()
        cls._initialized = True