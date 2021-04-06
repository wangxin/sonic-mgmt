"""
Run at exact fixed interval.
Reference: https://stackoverflow.com/questions/2697039/python-equivalent-of-setinterval
"""

import time
import threading

StartTime=time.time()

def action() :
    print('action ! -> time : {:.5f}s'.format(time.time()-StartTime))


class SetInterval :
    def __init__(self, interval, action, *args, **kwargs):
        self.interval = interval
        self.action = action
        self.args = args
        self.kwargs = kwargs
        self.stop_event = threading.Event()
        self.start_time = time.time()
        thread = threading.Thread(target=self._set_interval)
        thread.start()

    def _set_interval(self) :
        next_time = self.start_time + self.interval
        while not self.stop_event.wait(next_time - time.time()):
            next_time += self.interval
            self.action(*self.args, **self.kwargs)

    def cancel(self) :
        self.stop_event.set()

# start action every 0.6s
inter = SetInterval(0.6,action)
print('just after SetInterval -> time : {:.5f}s'.format(time.time()-StartTime))

# will stop interval in 5s
t = threading.Timer(20, inter.cancel)
t.start()
