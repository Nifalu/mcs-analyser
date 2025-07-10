class Config:
    default_var_length: int = 0
    input_hooks: list[str] = None
    output_hooks: list[str] = None
    _initialized = False

    @classmethod
    def init(cls, default_var_length: int = 0, input_hooks: list[str] = None, output_hooks: list[str] = None):
        cls.default_var_length = default_var_length
        cls.input_hooks = input_hooks
        cls.output_hooks = output_hooks
        cls._initialized = True