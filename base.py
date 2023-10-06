from json import load

class Config:
    def __init__(self, config_filename: str):
        with open(config_filename) as config:
            self.__dict__ = load(config)