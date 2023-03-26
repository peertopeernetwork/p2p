import os
import stat
import socket
import struct
import re
import collections
import time
import logging
import base64
import json
import gevent
from Config import config


def atomicWrite(dest, content, mode="wb"):
    try:
        with open(dest + "-tmpnew", mode) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if os.path.isfile(dest + "-tmpold"):
            os.rename(dest + "-tmpold", dest + "-tmpold-%s" % time.time())
        if os.path.isfile(dest):
            os.rename(dest, dest + "-tmpold")
        os.rename(dest + "-tmpnew", dest)
        if os.path.isfile(dest + "-tmpold"):
            os.unlink(dest + "-tmpold")
        return True
    except Exception as err:
        from Debug import Debug

        logging.error(
            "File %s write failed: %s, (%s) reverting…"
            % (dest, Debug.formatException(err), Debug.formatStack())
        )
        if os.path.isfile(dest + "-tmpold") and not os.path.isfile(dest):
            os.rename(dest + "-tmpold", dest)
        return False


def jsonDumps(data):
    content = json.dumps(data, indent=1, sort_keys=True)

    def compact_dict(match):
        if "\n" in match.group(0):
            return match.group(0).replace(
                match.group(1), match.group(1).strip()
            )
        else:
            return match.group(0)

    content = re.sub(
        r"\{(\n[^,\[{]{10,100000}?)}[, ]{0,2}\n",
        compact_dict,
        content,
        flags=re.DOTALL,
    )

    def compact_list(match):
        if "\n" in match.group(0):
            stripped_lines = re.sub("\n[ ]*", "", match.group(1))
            return match.group(0).replace(match.group(1), stripped_lines)
        else:
            return match.group(0)

    content = re.sub(
        r"\[([^\[{]{2,100000}?)][, ]{0,2}\n",
        compact_list,
        content,
        flags=re.DOTALL,
    )
    content = re.sub(r"(?m)[ ]+$", "", content)
    return content


def openLocked(path, mode="wb"):
    try:
        if os.name == "posix":
            import fcntl

            f = open(path, mode)
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif os.name == "nt":
            import msvcrt

            f = open(path, mode)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            f = open(path, mode)
    except (IOError, PermissionError, BlockingIOError) as err:
        raise BlockingIOError("Unable to lock file: %s" % err)
    return f


def getFreeSpace():
    free_space = -1
    if "statvfs" in dir(os):
        statvfs = os.statvfs(config.data_dir.encode("utf_8"))
        free_space = statvfs.f_frsize * statvfs.f_bavail
    else:
        try:
            import ctypes

            free_space_pointer = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(config.data_dir),
                None,
                None,
                ctypes.pointer(free_space_pointer),
            )
            free_space = free_space_pointer.value
        except Exception as err:
            logging.error("GetFreeSpace error: %s" % err)
    return free_space


def sqlquote(value):
    if type(value) is int:
        return str(value)
    else:
        return "'%s'" % value.replace("'", "''")


def shellquote(*args):
    if len(args) == 1:
        return '"%s"' % args[0].replace('"', "")
    else:
        return tuple(['"%s"' % arg.replace('"', "") for arg in args])


def packPeers(peers):
    packed_peers = {"ipv4": [], "ipv6": [], "onion": []}
    for peer in peers:
        try:
            ip_type = getIpType(peer.ip)
            if ip_type in packed_peers:
                packed_peers[ip_type].append(peer.packMyAddress())
        except Exception:
            logging.debug("Error packing peer address: %s" % peer)
    return packed_peers


def packAddress(ip, port):
    if ":" in ip:
        return socket.inet_pton(socket.AF_INET6, ip) + struct.pack("H", port)
    else:
        return socket.inet_aton(ip) + struct.pack("H", port)


def unpackAddress(packed):
    if len(packed) == 18:
        return (
            socket.inet_ntop(socket.AF_INET6, packed[0:16]),
            struct.unpack_from("H", packed, 16)[0],
        )
    else:
        if len(packed) != 6:
            raise Exception(
                "Invalid length ip4 packed address: %s" % len(packed)
            )
        return (
            socket.inet_ntoa(packed[0:4]),
            struct.unpack_from("H", packed, 4)[0],
        )


def packOnionAddress(onion, port):
    onion = onion.replace(".onion", "")
    return base64.b32decode(onion.upper()) + struct.pack("H", port)


def unpackOnionAddress(packed):
    return (
        base64.b32encode(packed[0:-2]).lower().decode() + ".onion",
        struct.unpack("H", packed[-2:])[0],
    )


def getDirname(path):
    if "/" in path:
        return path[: path.rfind("/") + 1].lstrip("/")
    else:
        return ""


def getFilename(path):
    return path[path.rfind("/") + 1 :]


def getFilesize(path):
    try:
        s = os.stat(path)
    except Exception:
        return None
    if stat.S_ISREG(s.st_mode):
        return s.st_size
    else:
        return None


def toHashId(hash):
    return int(hash[0:4], 16)


def mergeDicts(dicts):
    back = collections.defaultdict(set)
    for d in dicts:
        for key, val in d.items():
            back[key].update(val)
    return dict(back)


def httpRequest(url, as_file=False):
    if url.startswith("http://"):
        import urllib.request

        response = urllib.request.urlopen(url)
    else:
        import urllib.parse
        import socket
        import http.client
        import ssl
        from Plugin import PluginManager

        host, request = re.match("https://(.*?)(/.*?)$", url).groups()
        conn = http.client.HTTPSConnection(host)
        sock = socket.create_connection(
            (conn.host, conn.port), conn.timeout, conn.source_address
        )
        if "TrackerList" in PluginManager.plugin_manager.plugin_names:
            conn.sock = ssl.wrap_socket(sock, conn.key_file, conn.cert_file)
        else:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            conn.sock = context.wrap_socket(
                sock, conn.key_file, conn.cert_file
            )
        conn.request("GET", request)
        response = conn.getresponse()
        if response.status in [301, 302, 303, 307, 308]:
            logging.info("Redirect to: %s" % response.getheader("Location"))
            response = httpRequest(response.getheader("Location"))
    if as_file:
        import io

        data = io.BytesIO()
        while True:
            buff = response.read(1024 * 16)
            if not buff:
                break
            data.write(buff)
        return data
    else:
        return response


def timerCaller(secs, func, *args, **kwargs):
    gevent.spawn_later(secs, timerCaller, secs, func, *args, **kwargs)
    func(*args, **kwargs)


def timer(secs, func, *args, **kwargs):
    return gevent.spawn_later(secs, timerCaller, secs, func, *args, **kwargs)


def create_connection(address, timeout=None, source_address=None):
    if address in config.ip_local:
        sock = socket.create_connection_original(
            address, timeout, source_address
        )
    else:
        sock = socket.create_connection_original(
            address, timeout, socket.bind_addr
        )
    return sock


def socketBindMonkeyPatch(bind_ip, bind_port):
    import socket

    logging.info(
        "Monkey patching socket to bind to: %s:%s" % (bind_ip, bind_port)
    )
    socket.bind_addr = (bind_ip, int(bind_port))
    socket.create_connection_original = socket.create_connection
    socket.create_connection = create_connection


def limitedGzipFile(*args, **kwargs):
    import gzip

    class LimitedGzipFile(gzip.GzipFile):
        def read(self, size=-1):
            return super(LimitedGzipFile, self).read(1024 * 1024 * 25)

    return LimitedGzipFile(*args, **kwargs)


def avg(items):
    if len(items) > 0:
        return sum(items) / len(items)
    else:
        return 0


def isIp(ip):
    if ":" in ip:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except Exception:
            return False
    else:
        try:
            socket.inet_aton(ip)
            return True
        except Exception:
            return False


local_ip_pattern = re.compile(
    r"^127\.|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|169\.254\.|::1$|fe80"
)


def isPrivateIp(ip):
    return local_ip_pattern.match(ip)


def getIpType(ip):
    if ip.endswith(".onion"):
        return "onion"
    elif ":" in ip:
        return "ipv6"
    elif re.match(r"[0-9.]+$", ip):
        return "ipv4"
    else:
        return "unknown"


def createSocket(ip, sock_type=socket.SOCK_STREAM):
    ip_type = getIpType(ip)
    if ip_type == "ipv6":
        return socket.socket(socket.AF_INET6, sock_type)
    else:
        return socket.socket(socket.AF_INET, sock_type)


def getInterfaceIps(ip_type="ipv4"):
    res = []
    if ip_type == "ipv6":
        test_ips = ["ff0e::c", "2606:4700:4700::1111"]
    else:
        test_ips = ["239.255.255.250", "8.8.8.8"]
    for test_ip in test_ips:
        try:
            s = createSocket(test_ip, sock_type=socket.SOCK_DGRAM)
            s.connect((test_ip, 1))
            res.append(s.getsockname()[0])
        except Exception:
            pass
    try:
        res += [ip[4][0] for ip in socket.getaddrinfo(socket.gethostname(), 1)]
    except Exception:
        pass
    res = [
        re.sub("%.*", "", ip)
        for ip in res
        if getIpType(ip) == ip_type and isIp(ip)
    ]
    return list(set(res))


def cmp(a, b):
    return (a > b) - (a < b)


def encodeResponse(func):
    def wrapper(*args, **kwargs):
        back = func(*args, **kwargs)
        if "__next__" in dir(back):
            for part in back:
                if type(part) == bytes:
                    yield part
                else:
                    yield part.encode()
        else:
            if type(back) == bytes:
                yield back
            else:
                yield back.encode()

    return wrapper
