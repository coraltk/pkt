from src.colours import *

class Log:
    def __init__(self):
        self.c = Colours()

    def warn(self, s):
        print(f"{self.c.red}[!] {s}{self.c.reset}")
    
    def info(self, s):
        print(f"{self.c.blue}[~] {s}{self.c.reset}")
    
    def succ(self, s):
        print(f"{self.c.green}[*] {s}{self.c.reset}")
