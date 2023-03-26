import gevent
from Debug import Debug


class GreenletManager:
    def __init__(self, pool=None):
        self.greenlets = set()
        if not pool:
            pool = gevent.pool.Pool(None)
        self.pool = pool

    def _spawn_later(self, seconds, *args, **kwargs):
        if hasattr(self.pool, "spawnLater"):
            return self.pool.spawnLater(seconds, *args, **kwargs)
        greenlet = self.pool.greenlet_class(*args, **kwargs)
        self.pool.add(greenlet)
        greenlet.start_later(seconds)
        return greenlet

    def _spawn(self, *args, **kwargs):
        return self.pool.spawn(*args, **kwargs)

    def spawnLater(self, *args, **kwargs):
        greenlet = self._spawn_later(*args, **kwargs)
        greenlet.link(lambda greenlet: self.greenlets.remove(greenlet))
        self.greenlets.add(greenlet)
        return greenlet

    def spawn(self, *args, **kwargs):
        greenlet = self._spawn(*args, **kwargs)
        greenlet.link(lambda greenlet: self.greenlets.remove(greenlet))
        self.greenlets.add(greenlet)
        return greenlet

    def stopGreenlets(self, reason="Stopping all greenlets"):
        num = len(self.greenlets)
        gevent.killall(
            list(self.greenlets), Debug.createNotifyType(reason), block=False
        )
        return num
