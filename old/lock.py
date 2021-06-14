# coding=utf-8
from __future__ import unicode_literals

import time

from django.core.cache import cache

from bkmonitor.errors.collecting import LockTimeout


class CacheLock(object):
    def __init__(self, module, expires=60, wait_timeout=0):
        self.cache = cache
        self.module = module
        self.expires = expires  # 函数执行超时时间
        self.wait_timeout = wait_timeout  # 拿锁等待超时时间

    def get_lock(self, lock_key):
        # 获取cache锁
        wait_timeout = self.wait_timeout
        while wait_timeout >= 0:
            expires = time.time() + self.expires
            if self.cache.add(lock_key, expires, self.expires):
                return expires
            lock_value = self.cache.get(lock_key)
            if lock_value and lock_value < time.time():
                self.cache.set(lock_key, expires, self.expires)
                return expires
            wait_timeout -= 1
            time.sleep(1)
        raise LockTimeout({'msg': '当前有其他用户正在编辑该采集配置，请稍后重试'})

    def release_lock(self, lock_key, expires_time):
        # 释放cache锁
        lock_value = self.cache.get(lock_key)
        if lock_value == expires_time:
            self.cache.delete(lock_key)


def lock(cache_lock):
    def my_decorator(func):
        def wrapper(*args, **kwargs):
            collect_config = args[1]
            lock_key = 'bk_monitor:lock:{}_{}'.format(cache_lock.module, collect_config.id)
            expires_time = cache_lock.get_lock(lock_key)
            try:
                return func(*args, **kwargs)
            finally:
                cache_lock.release_lock(lock_key, expires_time)
        return wrapper
    return my_decorator
