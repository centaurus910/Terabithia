import yaml
import os
from pathlib import Path

class Config:
    def __init__(self, config='/configs/config.yaml'):
        current_path = os.getcwd()
        self.config = current_path + config
        self.file_path  = Path(self.config)

    def secrets(self, module):
        if self.file_path.is_file():
            try:
                secrets = yaml.safe_load(open(self.config))
                return secrets[module]
            except Exception as err:
                print(err)
        else:
            return False
