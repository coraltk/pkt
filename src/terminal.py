from src.colours import *

class Log:
    def __init__(self):
        self.c = Colours()

    def warn(self, s):
        print(f"{self.c.red}[!] {s}")
    
    def info(self, s):
        print(f"{self.c.blue}[~] {s}")
    
    def succ(self, s):
        print(f"{self.c.green}[*] {s}")
