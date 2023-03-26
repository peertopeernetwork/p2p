import logging
import time
import sys
import itertools
import collections
import gevent
import io
from Debug import Debug
from Config import config
from util import helper
from .PeerHashfield import PeerHashfield
from Plugin import PluginManager

if config.use_tempfiles:
    import tempfile


@PluginManager.acceptPlugins
class Peer(object):
    def __init__(self, ip, port, site=None, connection_server=None):
        self.ip = ip
        self.port = port
        self.site = site
        self.key = "%s:%s" % (ip, port)
        self.ip_type = None
        self.removed = False
        self.log_level = logging.DEBUG
        self.connection_error_log_level = logging.DEBUG
        self.connection = None
        self.connection_server = connection_server
        self.has_hashfield = False
        self.time_hashfield = None
        self.time_my_hashfield_sent = None
        self.time_found = time.time()
        self.time_response = 0
        self.time_added = time.time()
        self.last_ping = None
        self.last_pex = 0
        self.is_tracker_connection = False
        self.reputation = 0
        self.last_content_json_update = 0.0
        self.protected = 0
        self.reachable = None
        self.connection_error = 0
        self.hash_failed = 0
        self.download_bytes = 0
        self.download_time = 0
        self.protectedRequests = [
            "getFile",
            "streamFile",
            "update",
            "listModified",
        ]

    def __getattr__(self, key):
        if key == "hashfield":
            self.has_hashfield = True
            self.hashfield = PeerHashfield()
            return self.hashfield
        else:
            return object.__getattribute__(self, key)

    def log(self, text, log_level=None):
        if log_level is None:
            log_level = self.log_level
        if log_level <= logging.DEBUG:
            if not config.verbose:
                return
        logger = None
        if self.site:
            logger = self.site.log
        else:
            logger = logging.getLogger()
        logger.log(log_level, "%s:%s %s" % (self.ip, self.port, text))

    def markProtected(self, interval=60 * 2):
        self.protected = max(self.protected, time.time() + interval)

    def isProtected(self):
        if self.protected > 0:
            if self.protected < time.time():
                self.protected = 0
        return self.protected > 0

    def isTtlExpired(self, ttl):
        last_activity = max(self.time_found, self.time_response)
        return (time.time() - last_activity) > ttl

    def isConnected(self):
        if self.connection and not self.connection.connected:
            self.connection = None
        return self.connection and self.connection.connected

    def isConnectable(self):
        if self.connection_error >= 1:
            return False
        if time.time() - self.time_response > 60 * 60 * 2:
            return False
        return self.isReachable()

    def isReachable(self):
        if self.reachable is None:
            self.updateCachedState()
        return self.reachable

    def getIpType(self):
        if not self.ip_type:
            self.updateCachedState()
        return self.ip_type

    def updateCachedState(self):
        connection_server = self.getConnectionServer()
        if not self.port or self.port == 1:
            self.reachable = False
        else:
            self.reachable = connection_server.isIpReachable(self.ip)
        self.ip_type = connection_server.getIpType(self.ip)

    def getConnectionServer(self):
        if self.connection_server:
            connection_server = self.connection_server
        elif self.site:
            connection_server = self.site.connection_server
        else:
            import main

            connection_server = main.file_server
        return connection_server

    def connect(self, connection=None):
        if self.reputation < -10:
            self.reputation = -10
        if self.reputation > 10:
            self.reputation = 10
        if self.connection:
            self.log("Getting connection (Closing %s)…" % self.connection)
            self.connection.close("Connection change")
        else:
            self.log("Getting connection (reputation: %s)…" % self.reputation)
        if connection:
            self.log("Assigning connection %s" % connection)
            self.connection = connection
            self.connection.sites += 1
        else:
            self.connection = None
            try:
                connection_server = self.getConnectionServer()
                self.connection = connection_server.getConnection(
                    self.ip,
                    self.port,
                    site=self.site,
                    is_tracker_connection=self.is_tracker_connection,
                )
                if self.connection and self.connection.connected:
                    self.reputation += 1
                    self.connection.sites += 1
            except Exception as err:
                self.onConnectionError("Getting connection error")
                self.log(
                    "Getting connection error: %s (connection_error: %s,"
                    " hash_failed: %s)"
                    % (
                        Debug.formatException(err),
                        self.connection_error,
                        self.hash_failed,
                    ),
                    log_level=self.connection_error_log_level,
                )
                self.connection = None
        return self.connection

    def disconnect(self, reason="Unknown"):
        if self.connection:
            self.connection.close(reason)
            self.connection = None

    def findConnection(self):
        if self.connection and self.connection.connected:
            return self.connection
        else:
            self.connection = self.getConnectionServer().getConnection(
                self.ip, self.port, create=False, site=self.site
            )
            if self.connection:
                self.connection.sites += 1
        return self.connection

    def __str__(self):
        if self.site:
            return "Peer:%-12s of %s" % (self.ip, self.site.address_short)
        else:
            return "Peer:%-12s" % self.ip

    def __repr__(self):
        return "<%s>" % self.__str__()

    def packMyAddress(self):
        if self.ip.endswith(".onion"):
            return helper.packOnionAddress(self.ip, self.port)
        else:
            return helper.packAddress(self.ip, self.port)

    def found(self, source="other"):
        if self.reputation < 5:
            if source == "tracker":
                if self.ip.endswith(".onion"):
                    self.reputation += 1
                else:
                    self.reputation += 2
            elif source == "local":
                self.reputation += 20
        if source in ("tracker", "local"):
            self.site.peers_recent.appendleft(self)
        self.time_found = time.time()
        self.updateCachedState()

    def request(self, cmd, params={}, stream_to=None):
        if self.removed:
            return False
        if not self.connection or self.connection.closed:
            self.connect()
            if not self.connection:
                self.onConnectionError("Reconnect error")
                return None
        self.log(
            "Send request: %s %s %s %s"
            % (
                params.get("site", ""),
                cmd,
                params.get("inner_path", ""),
                params.get("location", ""),
            )
        )
        for retry in range(1, 4):
            try:
                if cmd in self.protectedRequests:
                    self.markProtected()
                if not self.connection:
                    raise Exception("No connection found")
                res = self.connection.request(cmd, params, stream_to)
                if not res:
                    raise Exception("Send error")
                if "error" in res:
                    self.log("%s error: %s" % (cmd, res["error"]))
                    self.onConnectionError("Response error")
                    break
                else:
                    self.connection_error = 0
                self.time_response = time.time()
                if res:
                    return res
                else:
                    raise Exception("Invalid response: %s" % res)
            except Exception as err:
                if type(err).__name__ == "Notify":
                    self.log(
                        "Peer worker got killed: %s, aborting cmd: %s"
                        % (err.message, cmd)
                    )
                    break
                else:
                    self.onConnectionError("Request error")
                    self.log(
                        "%s (connection_error: %s, hash_failed: %s, retry: %s)"
                        % (
                            Debug.formatException(err),
                            self.connection_error,
                            self.hash_failed,
                            retry,
                        )
                    )
                    time.sleep(1 * retry)
                    self.connect()
        return None

    def getFile(
        self,
        site,
        inner_path,
        file_size=None,
        pos_from=0,
        pos_to=None,
        streaming=False,
    ):
        if self.removed:
            return False
        if file_size and file_size > 5 * 1024 * 1024:
            max_read_size = 1024 * 1024
        else:
            max_read_size = 512 * 1024
        if pos_to:
            read_bytes = min(max_read_size, pos_to - pos_from)
        else:
            read_bytes = max_read_size
        location = pos_from
        if config.use_tempfiles:
            buff = tempfile.SpooledTemporaryFile(
                max_size=16 * 1024, mode="w+b"
            )
        else:
            buff = io.BytesIO()
        s = time.time()
        while True:
            if config.stream_downloads or read_bytes > 256 * 1024 or streaming:
                res = self.request(
                    "streamFile",
                    {
                        "site": site,
                        "inner_path": inner_path,
                        "location": location,
                        "read_bytes": read_bytes,
                        "file_size": file_size,
                    },
                    stream_to=buff,
                )
                if not res or "location" not in res:
                    return False
            else:
                self.log("Send: %s" % inner_path)
                res = self.request(
                    "getFile",
                    {
                        "site": site,
                        "inner_path": inner_path,
                        "location": location,
                        "read_bytes": read_bytes,
                        "file_size": file_size,
                    },
                )
                if not res or "location" not in res:
                    return False
                self.log("Recv: %s" % inner_path)
                buff.write(res["body"])
                res["body"] = None
            if res["location"] == res["size"] or res["location"] == pos_to:
                break
            else:
                location = res["location"]
                if pos_to:
                    read_bytes = min(max_read_size, pos_to - location)
        if pos_to:
            recv = pos_to - pos_from
        else:
            recv = res["location"]
        self.download_bytes += recv
        self.download_time += time.time() - s
        if self.site:
            self.site.settings["bytes_recv"] = (
                self.site.settings.get("bytes_recv", 0) + recv
            )
        self.log(
            "Downloaded: %s, pos: %s, read_bytes: %s"
            % (inner_path, buff.tell(), read_bytes)
        )
        buff.seek(0)
        return buff

    def ping(self, timeout=10.0, tries=3):
        if self.removed:
            return False
        response_time = None
        for retry in range(1, tries):
            s = time.time()
            with gevent.Timeout(timeout, False):
                res = self.request("ping")
                if res and "body" in res and res["body"] == b"Pong!":
                    response_time = time.time() - s
                    break
            self.onConnectionError("Ping timeout")
            self.connect()
            time.sleep(1)
        if response_time:
            self.log("Ping: %.3f" % response_time)
        else:
            self.log("Ping failed")
        self.last_ping = response_time
        return response_time

    def pex(self, site=None, need_num=5, request_interval=60 * 2):
        if self.removed:
            return False
        if not site:
            site = self.site
        if self.last_pex + request_interval >= time.time():
            return False
        self.last_pex = time.time()
        packed_peers = helper.packPeers(
            self.site.getConnectablePeers(5, allow_private=False)
        )
        request = {
            "site": site.address,
            "peers": packed_peers["ipv4"],
            "need": need_num,
        }
        if packed_peers["onion"]:
            request["peers_onion"] = packed_peers["onion"]
        if packed_peers["ipv6"]:
            request["peers_ipv6"] = packed_peers["ipv6"]
        res = self.request("pex", request)
        self.last_pex = time.time()
        if not res or "error" in res:
            return False
        added = 0
        if (
            "peers_ipv6" in res
            and self.connection
            and "ipv6" not in self.connection.server.supported_ip_types
        ):
            del res["peers_ipv6"]
        if (
            "peers_onion" in res
            and self.connection
            and "onion" not in self.connection.server.supported_ip_types
        ):
            del res["peers_onion"]
        for peer in itertools.chain(
            res.get("peers", []), res.get("peers_ipv6", [])
        ):
            address = helper.unpackAddress(peer)
            if site.addPeer(*address, source="pex"):
                added += 1
        for peer in res.get("peers_onion", []):
            address = helper.unpackOnionAddress(peer)
            if site.addPeer(*address, source="pex"):
                added += 1
        if added:
            self.log("Added peers using pex: %s" % added)
        return added

    def listModified(self, since):
        if self.removed:
            return False
        return self.request(
            "listModified", {"since": since, "site": self.site.address}
        )

    def updateHashfield(self, force=False):
        if self.removed:
            return False
        if (
            self.time_hashfield
            and time.time() - self.time_hashfield < 5 * 60
            and not force
        ):
            return False
        self.time_hashfield = time.time()
        res = self.request("getHashfield", {"site": self.site.address})
        if not res or "error" in res or "hashfield_raw" not in res:
            return False
        self.hashfield.replaceFromBytes(res["hashfield_raw"])
        return self.hashfield

    def findHashIds(self, hash_ids):
        if self.removed:
            return False
        res = self.request(
            "findHashIds", {"site": self.site.address, "hash_ids": hash_ids}
        )
        if not res or "error" in res or type(res) is not dict:
            return False
        back = collections.defaultdict(list)
        for ip_type in ["ipv4", "ipv6", "onion"]:
            if ip_type == "ipv4":
                key = "peers"
            else:
                key = "peers_%s" % ip_type
            for hash, peers in list(res.get(key, {}).items())[0:30]:
                if ip_type == "onion":
                    unpacker_func = helper.unpackOnionAddress
                else:
                    unpacker_func = helper.unpackAddress
                back[hash] += list(map(unpacker_func, peers))
        for hash in res.get("my", []):
            if self.connection:
                back[hash].append((self.connection.ip, self.connection.port))
            else:
                back[hash].append((self.ip, self.port))
        return back

    def sendMyHashfield(self):
        if self.connection and self.connection.handshake.get("rev", 0) < 510:
            return False
        if (
            self.time_my_hashfield_sent
            and self.site.content_manager.hashfield.time_changed
            <= self.time_my_hashfield_sent
        ):
            return False
        res = self.request(
            "setHashfield",
            {
                "site": self.site.address,
                "hashfield_raw": self.site.content_manager.hashfield.tobytes(),
            },
        )
        if not res or "error" in res:
            return False
        else:
            self.time_my_hashfield_sent = time.time()
            return True

    def publish(self, address, inner_path, body, modified, diffs=[]):
        if self.removed:
            return False
        if (
            len(body) > 10 * 1024
            and self.connection
            and self.connection.handshake.get("rev", 0) >= 4095
        ):
            body = b""
        return self.request(
            "update",
            {
                "site": address,
                "inner_path": inner_path,
                "body": body,
                "modified": modified,
                "diffs": diffs,
            },
        )

    def remove(self, reason="Removing"):
        self.removed = True
        self.log(
            "Removing peer with reason: <%s>. Connection error: %s, Hash"
            " failed: %s" % (reason, self.connection_error, self.hash_failed)
        )
        if self.site:
            self.site.deregisterPeer(self)
        self.disconnect(reason)

    def onConnectionError(self, reason="Unknown"):
        if not self.getConnectionServer().isInternetOnline():
            return
        self.connection_error += 1
        if self.site and len(self.site.peers) > 200:
            limit = 3
        else:
            limit = 6
        self.reputation -= 1
        if self.connection_error >= limit:
            self.remove(
                "Connection error limit reached: %s. Provided message: %s"
                % (limit, reason)
            )

    def onWorkerDone(self):
        pass
