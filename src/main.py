import os
import sys
import stat
import time
import logging
import loglevel_overrides

startup_errors = []


def startupError(msg):
    startup_errors.append(msg)
    print("Startup error: %s" % msg)


import gevent

if gevent.version_info.major <= 1:
    try:
        if "libev" not in str(gevent.config.loop):
            gevent.config.loop = "libev-cext"
    except Exception as err:
        startupError("Unable to switch gevent loop to libev: %s" % err)
import gevent.monkey

gevent.monkey.patch_all(thread=False, subprocess=False)
update_after_shutdown = False
restart_after_shutdown = False
from Config import config

config.parse(silent=True)
if not config.arguments:
    config.parse()
if not os.path.isdir(config.data_dir):
    os.mkdir(config.data_dir)
    try:
        os.chmod(config.data_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except Exception as err:
        startupError(
            "Can't change permission of %s: %s" % (config.data_dir, err)
        )
if not os.path.isfile("%s/sites.json" % config.data_dir):
    open("%s/sites.json" % config.data_dir, "w").write("{}")
if not os.path.isfile("%s/users.json" % config.data_dir):
    open("%s/users.json" % config.data_dir, "w").write("{}")
if config.action == "main":
    from util import helper

    try:
        lock = helper.openLocked("%s/lock.pid" % config.data_dir, "w")
        lock.write("%s" % os.getpid())
    except BlockingIOError as err:
        startupError(
            "Can't open lock file, your Peer-to-Peer Network client is"
            " probably already running, exiting… (%s)" % err
        )
        if config.open_browser and config.open_browser != "False":
            print("Opening browser: %s…", config.open_browser)
            import webbrowser

            try:
                if config.open_browser == "default_browser":
                    browser = webbrowser.get()
                else:
                    browser = webbrowser.get(config.open_browser)
                browser.open(
                    "http://%s:%s/%s"
                    % (
                        config.ui_ip if config.ui_ip != "*" else "127.0.0.1",
                        config.ui_port,
                        config.homepage,
                    ),
                    new=2,
                )
            except Exception as err:
                startupError("Error starting browser: %s" % err)
        sys.exit()
config.initLogging()
from Debug import DebugHook
from Plugin import PluginManager

PluginManager.plugin_manager.loadPlugins()
config.loadPlugins()
config.parse()
logging.debug("Config: %s" % config)
if config.stack_size:
    import threading

    threading.stack_size(config.stack_size)
if config.msgpack_purepython:
    os.environ["MSGPACK_PUREPYTHON"] = "True"
if sys.platform.startswith("win"):
    import subprocess

    try:
        chcp_res = (
            subprocess.check_output("chcp 65001", shell=True)
            .decode(errors="ignore")
            .strip()
        )
        logging.debug("Changed console encoding to utf_8: %s" % chcp_res)
    except Exception as err:
        logging.error("Error changing console encoding to utf_8: %s" % err)
if config.proxy:
    from util import SocksProxy
    import urllib.request

    logging.info("Patching sockets to socks proxy: %s" % config.proxy)
    if config.fileserver_ip == "*":
        config.fileserver_ip = "127.0.0.1"
    config.disable_udp = True
    SocksProxy.monkeyPatch(*config.proxy.split(":"))
elif config.tor == "always":
    from util import SocksProxy
    import urllib.request

    logging.info("Patching sockets to tor socks proxy: %s" % config.tor_proxy)
    if config.fileserver_ip == "*":
        config.fileserver_ip = "127.0.0.1"
    SocksProxy.monkeyPatch(*config.tor_proxy.split(":"))
    config.disable_udp = True
elif config.bind:
    bind = config.bind
    if ":" not in config.bind:
        bind += ":0"
    from util import helper

    helper.socketBindMonkeyPatch(*bind.split(":"))


@PluginManager.acceptPlugins
class Actions(object):
    def call(self, function_name, kwargs):
        logging.info(
            "Version: %s r%s, Python %s, Gevent: %s"
            % (config.version, config.rev, sys.version, gevent.__version__)
        )
        func = getattr(self, function_name, None)
        back = func(**kwargs)
        if back:
            print(back)

    def main(self):
        global ui_server, file_server
        from File import FileServer
        from Ui import UiServer

        logging.info("Creating FileServer…")
        file_server = FileServer()
        logging.info("Creating UiServer…")
        ui_server = UiServer()
        file_server.ui_server = ui_server
        for startup_error in startup_errors:
            logging.error("Startup error: %s" % startup_error)
        logging.info("Removing old SSL certs…")
        from Crypt import CryptConnection

        CryptConnection.manager.removeCerts()
        logging.info("Starting servers…")
        gevent.joinall(
            [gevent.spawn(ui_server.start), gevent.spawn(file_server.start)]
        )
        logging.info("All servers stopped")

    def siteCreate(self, use_master_seed=True):
        logging.info(
            "Generating new privatekey (use_master_seed: %s)…"
            % config.use_master_seed
        )
        from Crypt import CryptBitcoin

        if use_master_seed:
            from User import UserManager

            user = UserManager.user_manager.get()
            if not user:
                user = UserManager.user_manager.create()
            address, address_index, site_data = user.getNewSiteData()
            privatekey = site_data["privatekey"]
            logging.info(
                "Generated using master seed from users.json, site index: %s"
                % address_index
            )
        else:
            privatekey = CryptBitcoin.newPrivatekey()
            address = CryptBitcoin.privatekeyToAddress(privatekey)
        logging.info(
            "----------------------------------------------------------------------"
        )
        logging.info("Site private key: %s" % privatekey)
        logging.info(
            "                  !!! ^ Save it now, required to modify the site"
            " ^ !!!"
        )
        logging.info("Site address:     %s" % address)
        logging.info(
            "----------------------------------------------------------------------"
        )
        while True and not config.batch and not use_master_seed:
            if (
                input(
                    "? Have you secured your Bitcoin private key? (yes, no) > "
                ).lower()
                == "yes"
            ):
                break
            else:
                logging.info(
                    "Please, secure it now, you will need it to modify your"
                    " site!"
                )
        logging.info("Creating directory structure…")
        from Site.Site import Site
        from Site import SiteManager

        SiteManager.site_manager.load()
        os.mkdir("%s/%s" % (config.data_dir, address))
        open("%s/%s/index.html" % (config.data_dir, address), "w").write(
            "Your address is: %s" % address
        )
        logging.info("Creating content.json…")
        site = Site(address)
        extend = {"postmessage_nonce_security": True}
        if use_master_seed:
            extend["address_index"] = address_index
        site.content_manager.sign(privatekey=privatekey, extend=extend)
        site.settings["own"] = True
        site.saveSettings()
        logging.info("Site created!")

    def siteSign(
        self,
        address,
        privatekey=None,
        inner_path="content.json",
        publish=False,
        remove_missing_optional=False,
    ):
        from Site.Site import Site
        from Site import SiteManager
        from Debug import Debug

        SiteManager.site_manager.load()
        logging.info("Signing site: %s…" % address)
        site = Site(address, allow_create=False)
        if not privatekey:
            from User import UserManager

            user = UserManager.user_manager.get()
            if user:
                site_data = user.getSiteData(address)
                privatekey = site_data.get("privatekey")
            else:
                privatekey = None
            if not privatekey:
                import getpass

                privatekey = getpass.getpass("Private key (input hidden):")
        try:
            succ = site.content_manager.sign(
                inner_path=inner_path,
                privatekey=privatekey,
                update_changed_files=True,
                remove_missing_optional=remove_missing_optional,
            )
        except Exception as err:
            logging.error("Sign error: %s" % Debug.formatException(err))
            succ = False
        if succ and publish:
            self.sitePublish(address, inner_path=inner_path)

    def siteVerify(self, address):
        import time
        from Site.Site import Site
        from Site import SiteManager

        SiteManager.site_manager.load()
        s = time.time()
        logging.info("Verifying site: %s…" % address)
        site = Site(address)
        bad_files = []
        for content_inner_path in site.content_manager.contents:
            s = time.time()
            logging.info("Verifying %s signature…" % content_inner_path)
            err = None
            try:
                file_correct = site.content_manager.verifyFile(
                    content_inner_path,
                    site.storage.open(content_inner_path, "rb"),
                    ignore_same=False,
                )
            except Exception as err:
                file_correct = False
            if file_correct is True:
                logging.info(
                    "[OK] %s (Done in %.3fs)"
                    % (content_inner_path, time.time() - s)
                )
            else:
                logging.error(
                    "[ERROR] %s: invalid file: %s!" % (content_inner_path, err)
                )
                input("Continue?")
                bad_files += content_inner_path
        logging.info("Verifying site files…")
        bad_files += site.storage.verifyFiles()["bad_files"]
        if not bad_files:
            logging.info(
                "[OK] All file sha512sum matches! (%.3fs)" % (time.time() - s)
            )
        else:
            logging.error("[ERROR] Error during verifying site files!")

    def dbRebuild(self, address):
        from Site.Site import Site
        from Site import SiteManager

        SiteManager.site_manager.load()
        logging.info("Rebuilding site sql cache: %s…" % address)
        site = SiteManager.site_manager.get(address)
        s = time.time()
        try:
            site.storage.rebuildDb()
            logging.info("Done in %.3fs" % (time.time() - s))
        except Exception as err:
            logging.error(err)

    def dbQuery(self, address, query):
        from Site.Site import Site
        from Site import SiteManager

        SiteManager.site_manager.load()
        import json

        site = Site(address)
        result = []
        for row in site.storage.query(query):
            result.append(dict(row))
        print(json.dumps(result, indent=4))

    def siteAnnounce(self, address):
        from Site.Site import Site
        from Site import SiteManager

        SiteManager.site_manager.load()
        logging.info("Opening a simple connection server")
        global file_server
        from File import FileServer

        file_server = FileServer("127.0.0.1", 55654)
        file_server.start()
        logging.info("Announcing site %s to tracker…" % address)
        site = Site(address)
        s = time.time()
        site.announce()
        print("Response time: %.3fs" % (time.time() - s))
        print(site.peers)

    def siteDownload(self, address):
        import gevent.event
        from Site.Site import Site
        from Site import SiteManager

        SiteManager.site_manager.load()
        logging.info("Opening a simple connection server")
        global file_server
        from File import FileServer

        file_server = FileServer("127.0.0.1", 55654)
        file_server_thread = gevent.spawn(file_server.start, check_sites=False)
        site = Site(address)
        on_completed = gevent.event.AsyncResult()

        def onComplete(evt):
            evt.set(True)

        site.onComplete.once(lambda: onComplete(on_completed))
        print("Announcing…")
        site.announce()
        s = time.time()
        print("Downloading…")
        site.downloadContent("content.json", check_modifications=True)
        print("Downloaded in %.3fs" % (time.time() - s))

    def siteNeedFile(self, address, inner_path):
        from Site.Site import Site
        from Site import SiteManager

        SiteManager.site_manager.load()

        def checker():
            while 1:
                s = time.time()
                time.sleep(1)
                print("Switch time:", time.time() - s)

        gevent.spawn(checker)
        logging.info("Opening a simple connection server")
        global file_server
        from File import FileServer

        file_server = FileServer("127.0.0.1", 55654)
        file_server_thread = gevent.spawn(file_server.start, check_sites=False)
        site = Site(address)
        site.announce()
        print(site.needFile(inner_path, update=True))

    def siteCmd(self, address, cmd, parameters):
        import json
        from Site import SiteManager

        site = SiteManager.site_manager.get(address)
        if not site:
            logging.error("Site not found: %s" % address)
            return None
        ws = self.getWebsocket(site)
        ws.send(json.dumps({"cmd": cmd, "params": parameters, "id": 1}))
        res_raw = ws.recv()
        try:
            res = json.loads(res_raw)
        except Exception as err:
            return {"error": "Invalid result: %s" % err, "res_raw": res_raw}
        if "result" in res:
            return res["result"]
        else:
            return res

    def getWebsocket(self, site):
        import websocket

        ws_address = "ws://%s:%s/Websocket?wrapper_key=%s" % (
            config.ui_ip,
            config.ui_port,
            site.settings["wrapper_key"],
        )
        logging.info("Connecting to %s" % ws_address)
        ws = websocket.create_connection(ws_address)
        return ws

    def sitePublish(
        self, address, peer_ip=None, peer_port=55568, inner_path="content.json"
    ):
        global file_server
        from Site.Site import Site
        from Site import SiteManager
        from File import (
            FileServer,
        )
        from Peer import Peer

        file_server = FileServer()
        site = SiteManager.site_manager.get(address)
        logging.info("Loading site…")
        site.settings["serving"] = True
        try:
            ws = self.getWebsocket(site)
            logging.info("Sending siteReload")
            self.siteCmd(address, "siteReload", inner_path)
            logging.info("Sending sitePublish")
            self.siteCmd(
                address,
                "sitePublish",
                {"inner_path": inner_path, "sign": False},
            )
            logging.info("Done.")
        except Exception as err:
            logging.info("Can't connect to local websocket client: %s" % err)
            logging.info("Creating FileServer…")
            file_server_thread = gevent.spawn(
                file_server.start, check_sites=False
            )
            time.sleep(0.001)
            file_server.portCheck()
            if peer_ip:
                site.addPeer(peer_ip, peer_port)
            else:
                logging.info("Gathering peers from tracker")
                site.announce()
            published = site.publish(5, inner_path)
            if published > 0:
                time.sleep(3)
                logging.info("Serving files (max 60s)…")
                gevent.joinall([file_server_thread], timeout=60)
                logging.info("Done.")
            else:
                logging.info(
                    "No peers found, sitePublish command only works if you"
                    " already have visitors serving your site"
                )

    def cryptPrivatekeyToAddress(self, privatekey=None):
        from Crypt import CryptBitcoin

        if not privatekey:
            import getpass

            privatekey = getpass.getpass("Private key (input hidden):")
        print(CryptBitcoin.privatekeyToAddress(privatekey))

    def cryptSign(self, message, privatekey):
        from Crypt import CryptBitcoin

        print(CryptBitcoin.sign(message, privatekey))

    def cryptVerify(self, message, sign, address):
        from Crypt import CryptBitcoin

        print(CryptBitcoin.verify(message, address, sign))

    def cryptGetPrivatekey(self, master_seed, site_address_index=None):
        from Crypt import CryptBitcoin

        if len(master_seed) != 64:
            logging.error(
                "Error: Invalid master seed length: %s (required: 64)"
                % len(master_seed)
            )
            return False
        privatekey = CryptBitcoin.hdPrivatekey(master_seed, site_address_index)
        print("Requested private key: %s" % privatekey)

    def peerPing(self, peer_ip, peer_port=None):
        if not peer_port:
            peer_port = 55568
        logging.info("Opening a simple connection server")
        global file_server
        from Connection import ConnectionServer

        file_server = ConnectionServer("127.0.0.1", 55654)
        file_server.start(check_connections=False)
        from Crypt import CryptConnection

        CryptConnection.manager.loadCerts()
        from Peer import Peer

        logging.info(
            "Pinging 5 times peer: %s:%s…" % (peer_ip, int(peer_port))
        )
        s = time.time()
        peer = Peer(peer_ip, peer_port)
        peer.connect()
        if not peer.connection:
            print(
                "Error: Can't connect to peer (connection error: %s)"
                % peer.connection_error
            )
            return False
        if "shared_ciphers" in dir(peer.connection.sock):
            print("Shared ciphers:", peer.connection.sock.shared_ciphers())
        if "cipher" in dir(peer.connection.sock):
            print("Cipher:", peer.connection.sock.cipher()[0])
        if "version" in dir(peer.connection.sock):
            print("TLS version:", peer.connection.sock.version())
        print(
            "Connection time: %.3fs  (connection error: %s)"
            % (time.time() - s, peer.connection_error)
        )
        for i in range(5):
            ping_delay = peer.ping()
            print("Response time: %.3fs" % ping_delay)
            time.sleep(1)
        peer.remove()
        print("Reconnect test…")
        peer = Peer(peer_ip, peer_port)
        for i in range(5):
            ping_delay = peer.ping()
            print("Response time: %.3fs" % ping_delay)
            time.sleep(1)

    def peerGetFile(self, peer_ip, peer_port, site, filename, benchmark=False):
        logging.info("Opening a simple connection server")
        global file_server
        from Connection import ConnectionServer

        file_server = ConnectionServer("127.0.0.1", 55654)
        file_server.start(check_connections=False)
        from Crypt import CryptConnection

        CryptConnection.manager.loadCerts()
        from Peer import Peer

        logging.info(
            "Getting %s/%s from peer: %s:%s…"
            % (site, filename, peer_ip, peer_port)
        )
        peer = Peer(peer_ip, peer_port)
        s = time.time()
        if benchmark:
            for i in range(10):
                peer.getFile(site, filename),
            print("Response time: %.3fs" % (time.time() - s))
            input("Check memory")
        else:
            print(peer.getFile(site, filename).read())

    def peerCmd(self, peer_ip, peer_port, cmd, parameters):
        logging.info("Opening a simple connection server")
        global file_server
        from Connection import ConnectionServer

        file_server = ConnectionServer()
        file_server.start(check_connections=False)
        from Crypt import CryptConnection

        CryptConnection.manager.loadCerts()
        from Peer import Peer

        peer = Peer(peer_ip, peer_port)
        import json

        if parameters:
            parameters = json.loads(parameters.replace("'", '"'))
        else:
            parameters = {}
        try:
            res = peer.request(cmd, parameters)
            print(json.dumps(res, indent=2, ensure_ascii=False))
        except Exception as err:
            print("Unknown response (%s): %s" % (err, res))

    def getConfig(self):
        import json

        print(json.dumps(config.getServerInfo(), indent=2, ensure_ascii=False))

    def test(self, test_name, *args, **kwargs):
        import types

        def funcToName(func_name):
            test_name = func_name.replace("test", "")
            return test_name[0].lower() + test_name[1:]

        test_names = [
            funcToName(name)
            for name in dir(self)
            if name.startswith("test") and name != "test"
        ]
        if not test_name:
            print("\nNo test specified, possible tests:")
            for test_name in test_names:
                func_name = "test" + test_name[0].upper() + test_name[1:]
                func = getattr(self, func_name)
                if func.__doc__:
                    print("- %s: %s" % (test_name, func.__doc__.strip()))
                else:
                    print("- %s" % test_name)
            return None
        func_name = "test" + test_name[0].upper() + test_name[1:]
        if hasattr(self, func_name):
            func = getattr(self, func_name)
            print("- Running test: %s" % test_name, end="")
            s = time.time()
            ret = func(*args, **kwargs)
            if isinstance(ret, types.GeneratorType):
                for progress in ret:
                    print(progress, end="")
                    sys.stdout.flush()
            print("\n* Test %s done in %.3fs" % (test_name, time.time() - s))
        else:
            print(
                "Unknown test: %r (choose from: %s)" % (test_name, test_names)
            )


actions = Actions()


def start():
    action_kwargs = config.getActionArguments()
    actions.call(config.action, action_kwargs)
