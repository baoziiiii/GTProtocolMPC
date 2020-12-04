import time

class timer:
    def __init__(self):
        self.start_time = None
        self.pause_time = None

    def start(self):
        if self.start_time == None:
            self.start_time = time.time()
        elif self.pause_time != None:
            self.start_time += time.time() - self.pause_time
        self.pause_time = None

    def pause(self):
        self.pause_time = time.time()

    def record(self):
        if self.pause_time != None:
            return self.pause_time - self.start_time
        if self.start_time != None:
            return time.time() - self.start_time
        return 0