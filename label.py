from typing import *

class Label:
    name: Optional[str]
    rva: int
    index: int # いる？
    def __init__(self, rva: int, name : str = ""):
        self.rva = rva
        self.name = name
        self.index = 0
        pass
