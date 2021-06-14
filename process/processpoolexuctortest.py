# -*- encoing=utf-8 -*-


import os
import time
from concurrent.futures import ProcessPoolExecutor





def _task():
    for i in range(2):
        print('this is a _task. i = {}. process id = {}'.format(i, os.getpid()))
        time.sleep(1)
    return time.time()


if __name__ == '__main__':
    futures = []
    pp = ProcessPoolExecutor(10)
    for i in range(10):
        future = pp.submit(_task)
        futures.append(future)

    print("I am here")
    for future in futures:
        print(future.result())
