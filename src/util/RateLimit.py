import time
import gevent
import logging

log = logging.getLogger("RateLimit")
called_db = {}
queue_db = {}


def called(event, penalty=0):
    called_db[event] = time.time() + penalty


def isAllowed(event, allowed_again=10):
    last_called = called_db.get(event)
    if not last_called:
        return True
    elif time.time() - last_called >= allowed_again:
        del called_db[event]
        return True
    else:
        return False


def delayLeft(event, allowed_again=10):
    last_called = called_db.get(event)
    if not last_called:
        return 0
    else:
        return allowed_again - (time.time() - last_called)


def callQueue(event):
    func, args, kwargs, thread = queue_db[event]
    log.debug("Calling: %s" % event)
    called(event)
    del queue_db[event]
    return func(*args, **kwargs)


def callAsync(event, allowed_again=10, func=None, *args, **kwargs):
    if isAllowed(event, allowed_again):
        called(event)
        return gevent.spawn(func, *args, **kwargs)
    else:
        time_left = allowed_again - max(0, time.time() - called_db[event])
        log.debug("Added to queue (%.2fs left): %s " % (time_left, event))
        if not queue_db.get(event):
            thread = gevent.spawn_later(time_left, lambda: callQueue(event))
            queue_db[event] = (func, args, kwargs, thread)
            return thread
        else:
            thread = queue_db[event][3]
            queue_db[event] = (func, args, kwargs, thread)
            return thread


def call(event, allowed_again=10, func=None, *args, **kwargs):
    if isAllowed(event):
        called(event)
        return func(*args, **kwargs)
    else:
        time_left = max(0, allowed_again - (time.time() - called_db[event]))
        log.debug("Calling sync (%.2fs left): %s" % (time_left, event))
        called(event, time_left)
        time.sleep(time_left)
        back = func(*args, **kwargs)
        called(event)
        return back


def rateLimitCleanup():
    while 1:
        expired = time.time() - 60 * 2
        for event in list(called_db.keys()):
            if called_db[event] < expired:
                del called_db[event]
        time.sleep(60 * 3)


gevent.spawn(rateLimitCleanup)
if __name__ == "__main__":
    from gevent import monkey

    monkey.patch_all()
    import random

    def publish(inner_path):
        print("Publishing %s…" % inner_path)
        return 1

    def cb(thread):
        print("Value:", thread.value)

    print("Testing async spam requests rate limit to 1/sec…")
    for i in range(3000):
        thread = callAsync(
            "publish content.json", 1, publish, "content.json %s" % i
        )
        time.sleep(float(random.randint(1, 20)) / 100000)
    print(thread.link(cb))
    print("Done")
    time.sleep(2)
    print("Testing sync spam requests rate limit to 1/sec…")
    for i in range(5):
        call("publish data.json", 1, publish, "data.json %s" % i)
        time.sleep(float(random.randint(1, 100)) / 100)
    print("Done")
    print("Testing cleanup")
    thread = callAsync(
        "publish content.json single", 1, publish, "content.json single"
    )
    print("Needs to cleanup:", called_db, queue_db)
    print("Waiting 3min for cleanup process…")
    time.sleep(60 * 3)
    print("Cleaned up:", called_db, queue_db)
