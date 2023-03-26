import time
import weakref
import gevent


class ConnectRequirement(object):
    next_id = 1

    def __init__(
        self, need_nr_peers, need_nr_connected_peers, expiration_interval=None
    ):
        self.need_nr_peers = need_nr_peers
        self.need_nr_connected_peers = need_nr_connected_peers
        self.result = gevent.event.AsyncResult()
        self.result_connected = gevent.event.AsyncResult()
        self.expiration_interval = expiration_interval
        self.expired = False
        if expiration_interval:
            self.expire_at = time.time() + expiration_interval
        else:
            self.expire_at = None
        self.nr_peers = -1
        self.nr_connected_peers = -1
        self.heartbeat = gevent.event.AsyncResult()
        self.id = type(self).next_id
        type(self).next_id += 1

    def fulfilled(self):
        return self.result.ready() and self.result_connected.ready()

    def ready(self):
        return self.expired or self.fulfilled()

    def waitHeartbeat(self, timeout=None):
        if self.heartbeat.ready():
            self.heartbeat = gevent.event.AsyncResult()
        return self.heartbeat.wait(timeout=timeout)

    def sendHeartbeat(self):
        self.heartbeat.set_result()
        if self.heartbeat.ready():
            self.heartbeat = gevent.event.AsyncResult()


class PeerConnector(object):
    def __init__(self, site):
        self.site = site
        self.peer_reqs = weakref.WeakValueDictionary()
        self.peer_connector_controller = None
        self.peer_connector_workers = dict()
        self.peer_connector_worker_limit = 5
        self.peer_connector_announcer = None
        self.need_nr_peers = 0
        self.need_nr_connected_peers = 0
        self.nr_peers = 0
        self.nr_connected_peers = 0
        self.peers = list()

    def addReq(self, req):
        self.peer_reqs[req.id] = req
        self.processReqs()

    def newReq(
        self, need_nr_peers, need_nr_connected_peers, expiration_interval=None
    ):
        req = ConnectRequirement(
            need_nr_peers,
            need_nr_connected_peers,
            expiration_interval=expiration_interval,
        )
        self.addReq(req)
        return req

    def processReqs(self, nr_connected_peers=None):
        nr_peers = len(self.site.peers)
        self.nr_peers = nr_peers
        need_nr_peers = 0
        need_nr_connected_peers = 0
        items = list(self.peer_reqs.items())
        for key, req in items:
            send_heartbeat = False
            if req.expire_at and req.expire_at < time.time():
                req.expired = True
                self.peer_reqs.pop(key, None)
                send_heartbeat = True
            elif req.result.ready() and req.result_connected.ready():
                pass
            else:
                if nr_connected_peers is not None:
                    if (
                        req.need_nr_peers <= nr_peers
                        and req.need_nr_connected_peers <= nr_connected_peers
                    ):
                        req.result.set_result(nr_peers)
                        req.result_connected.set_result(nr_connected_peers)
                        send_heartbeat = True
                    if (
                        req.nr_peers != nr_peers
                        or req.nr_connected_peers != nr_connected_peers
                    ):
                        req.nr_peers = nr_peers
                        req.nr_connected_peers = nr_connected_peers
                        send_heartbeat = True
                if not (req.result.ready() and req.result_connected.ready()):
                    need_nr_peers = max(need_nr_peers, req.need_nr_peers)
                    need_nr_connected_peers = max(
                        need_nr_connected_peers, req.need_nr_connected_peers
                    )
            if send_heartbeat:
                req.sendHeartbeat()
        self.need_nr_peers = need_nr_peers
        self.need_nr_connected_peers = need_nr_connected_peers
        if nr_connected_peers is None:
            nr_connected_peers = 0
        if need_nr_peers > nr_peers:
            self.spawnPeerConnectorAnnouncer()
        if need_nr_connected_peers > nr_connected_peers:
            self.spawnPeerConnectorController()

    def processReqs2(self):
        self.nr_connected_peers = len(
            self.site.getConnectedPeers(only_fully_connected=True)
        )
        self.processReqs(nr_connected_peers=self.nr_connected_peers)

    def addPeer(self, peer):
        if not self.peers:
            return
        if peer not in self.peers:
            self.peers.append(peer)

    def deregisterPeer(self, peer):
        try:
            self.peers.remove(peer)
        except:
            pass

    def sleep(self, t):
        self.site.connection_server.sleep(t)

    def keepGoing(self):
        return (
            self.site.isServing()
            and self.site.connection_server.allowsCreatingConnections()
        )

    def peerConnectorWorker(self, peer):
        if not peer.isConnected():
            peer.connect()
        if peer.isConnected():
            peer.ping()
            self.processReqs2()

    def peerConnectorController(self):
        self.peers = list()
        addendum = 20
        while self.keepGoing():
            no_peers_loop = 0
            while len(self.site.peers) < 1:
                self.sleep(10 + no_peers_loop)
                no_peers_loop += 1
                if not self.keepGoing() or no_peers_loop > 60:
                    break
            self.processReqs2()
            if self.need_nr_connected_peers <= self.nr_connected_peers:
                break
            if len(self.site.peers) < 1:
                break
            if len(self.peers) < 1:
                self.peers = self.site.getRecentPeers(
                    self.need_nr_connected_peers * 2
                    + self.nr_connected_peers
                    + addendum
                )
                addendum = min(addendum * 2 + 50, 10000)
                if len(self.peers) <= self.nr_connected_peers:
                    self.site.announcer.announcePex(
                        establish_connections=False
                    )
                    self.sleep(10)
                    continue
            added = 0
            while (
                self.keepGoing()
                and len(self.peer_connector_workers)
                < self.peer_connector_worker_limit
            ):
                if len(self.peers) < 1:
                    break
                peer = self.peers.pop(0)
                if peer.isConnected():
                    continue
                thread = self.peer_connector_workers.get(peer, None)
                if thread:
                    continue
                thread = self.site.spawn(self.peerConnectorWorker, peer)
                self.peer_connector_workers[peer] = thread
                thread.link(
                    lambda thread, peer=peer: self.peer_connector_workers.pop(
                        peer, None
                    )
                )
                added += 1
            if not self.keepGoing():
                break
            if not added:
                self.sleep(20)
            while (
                self.keepGoing()
                and len(self.peer_connector_workers)
                >= self.peer_connector_worker_limit
            ):
                self.sleep(2)
            if not self.site.connection_server.isInternetOnline():
                self.sleep(30)
        self.peers = list()
        self.peer_connector_controller = None

    def peerConnectorAnnouncer(self):
        while self.keepGoing():
            if self.need_nr_peers <= self.nr_peers:
                break
            self.site.announce(mode="more")
            self.processReqs2()
            if self.need_nr_peers <= self.nr_peers:
                break
            self.sleep(10)
            if not self.site.connection_server.isInternetOnline():
                self.sleep(20)
        self.peer_connector_announcer = None

    def spawnPeerConnectorController(self):
        if (
            self.peer_connector_controller is None
            or self.peer_connector_controller.ready()
        ):
            self.peer_connector_controller = self.site.spawn(
                self.peerConnectorController
            )

    def spawnPeerConnectorAnnouncer(self):
        if (
            self.peer_connector_announcer is None
            or self.peer_connector_announcer.ready()
        ):
            self.peer_connector_announcer = self.site.spawn(
                self.peerConnectorAnnouncer
            )
