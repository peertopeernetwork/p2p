import logging
import time
import random
import socket
import sys
import weakref
import gevent
import gevent.pool
from gevent.server import StreamServer
import util
from util import helper
from Config import config
from .FileRequest import FileRequest
from Peer import PeerPortchecker
from Site import SiteManager
from Connection import ConnectionServer
from Plugin import PluginManager
from Debug import Debug

log = logging.getLogger("FileServer")


class FakeThread(object):
    def __init__(self):
        pass

    def ready(self):
        return False


@PluginManager.acceptPlugins
class FileServer(ConnectionServer):
    def __init__(
        self,
        ip=config.fileserver_ip,
        port=config.fileserver_port,
        ip_type=config.fileserver_ip_type,
    ):
        self.site_manager = SiteManager.site_manager
        self.portchecker = PeerPortchecker.PeerPortchecker(self)
        self.ip_type = ip_type
        self.ip_external_list = []
        self.recheck_port = True
        self.active_mode_thread_pool = gevent.pool.Pool(None)
        self.site_pool = gevent.pool.Pool(None)
        self.update_pool = gevent.pool.Pool(10)
        self.update_start_time = 0
        self.update_sites_task_next_nr = 1
        self.update_threads = weakref.WeakValueDictionary()
        self.passive_mode = None
        self.active_mode = None
        self.active_mode_threads = {}
        self.supported_ip_types = ["ipv4"]
        if self.getIpType(ip) == "ipv6" or self.isIpv6Supported():
            self.supported_ip_types.append("ipv6")
        if ip_type == "ipv6" or (
            ip_type == "dual" and "ipv6" in self.supported_ip_types
        ):
            ip = ip.replace("*", "::")
        else:
            ip = ip.replace("*", "0.0.0.0")
        if config.tor == "always":
            port = config.tor_hs_port
            config.fileserver_port = port
        elif port == 0:
            port_range_from, port_range_to = list(
                map(int, config.fileserver_port_range.split("-"))
            )
            port = self.getRandomPort(ip, port_range_from, port_range_to)
            config.fileserver_port = port
            if not port:
                raise Exception("Can't find bindable port")
            if not config.tor == "always":
                config.saveValue("fileserver_port", port)
                config.arguments.fileserver_port = port
        ConnectionServer.__init__(self, ip, port, self.handleRequest)
        log.debug("Supported IP types: %s" % self.supported_ip_types)
        self.managed_pools["active_mode_thread"] = self.active_mode_thread_pool
        self.managed_pools["update"] = self.update_pool
        self.managed_pools["site"] = self.site_pool
        if ip_type == "dual" and ip == "::":
            try:
                log.debug("Binding proxy to %s:%s" % ("::", self.port))
                self.stream_server_proxy = StreamServer(
                    ("0.0.0.0", self.port),
                    self.handleIncomingConnection,
                    spawn=self.pool,
                    backlog=100,
                )
            except Exception as err:
                log.info(
                    "StreamServer proxy create error: %s"
                    % Debug.formatException(err)
                )
        self.port_opened = {}
        self.last_request = time.time()
        self.files_parsing = {}
        self.ui_server = None

    def getSites(self):
        sites = self.site_manager.list()
        self.sites = sites
        return sites

    def getSite(self, address):
        return self.getSites().get(address, None)

    def getSiteAddresses(self):
        return [
            site.address
            for site in sorted(
                list(self.getSites().values()),
                key=lambda site: site.settings.get("modified", 0),
                reverse=True,
            )
        ]

    def getRandomPort(self, ip, port_range_from, port_range_to):
        log.info(
            "Getting random port in range %s-%s…"
            % (port_range_from, port_range_to)
        )
        tried = []
        for bind_retry in range(100):
            port = random.randint(port_range_from, port_range_to)
            if port in tried:
                continue
            tried.append(port)
            sock = helper.createSocket(ip)
            try:
                sock.bind((ip, port))
                success = True
            except Exception as err:
                log.warning("Error binding to port %s: %s" % (port, err))
                success = False
            sock.close()
            if success:
                log.info("Found unused random port: %s" % port)
                return port
            else:
                self.sleep(0.1)
        return False

    def isIpv6Supported(self):
        if config.tor == "always":
            return True
        ipv6_testip = "fcec:ae97:8902:d810:6c92:ec67:efb2:3ec5"
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.connect((ipv6_testip, 80))
            local_ipv6 = sock.getsockname()[0]
            if local_ipv6 == "::1":
                log.debug("IPv6 not supported, no local IPv6 address")
                return False
            else:
                log.debug("IPv6 supported on IP %s" % local_ipv6)
                return True
        except socket.error as err:
            log.warning("IPv6 not supported: %s" % err)
            return False
        except Exception as err:
            log.error("IPv6 check error: %s" % err)
            return False

    def listenProxy(self):
        try:
            self.stream_server_proxy.serve_forever()
        except Exception as err:
            if err.errno == 98:
                log.debug("StreamServer proxy listen error: %s" % err)
            else:
                log.info("StreamServer proxy listen error: %s" % err)

    def handleRequest(self, connection, message):
        if config.verbose:
            if "params" in message:
                log.debug(
                    "FileRequest: %s %s %s %s"
                    % (
                        str(connection),
                        message["cmd"],
                        message["params"].get("site"),
                        message["params"].get("inner_path"),
                    )
                )
            else:
                log.debug(
                    "FileRequest: %s %s" % (str(connection), message["cmd"])
                )
        req = FileRequest(self, connection)
        req.route(message["cmd"], message.get("req_id"), message.get("params"))
        if not connection.is_private_ip:
            self.setInternetStatus(True)

    def onInternetOnline(self):
        log.info("Internet online")
        invalid_interval = (
            self.internet_offline_since
            - self.internet_outage_threshold
            - random.randint(60 * 5, 60 * 10),
            time.time(),
        )
        self.invalidateUpdateTime(invalid_interval)
        self.recheck_port = True
        self.spawn(self.updateSites)

    def reload(self):
        global FileRequest
        from importlib.machinery import SourceFileLoader

        FileRequest = SourceFileLoader(
            "FileRequest", "src/File/FileRequest.py"
        ).FileRequest

    def portCheck(self):
        if self.isOfflineMode():
            log.info("Offline mode: port check disabled")
            res = {"ipv4": None, "ipv6": None}
            self.port_opened = res
            return res
        if config.ip_external:
            for ip_external in config.ip_external:
                SiteManager.peer_blacklist.append((ip_external, self.port))
            ip_external_types = set(
                [self.getIpType(ip) for ip in config.ip_external]
            )
            res = {
                "ipv4": "ipv4" in ip_external_types,
                "ipv6": "ipv6" in ip_external_types,
            }
            self.ip_external_list = config.ip_external
            self.port_opened.update(res)
            log.info(
                "Server port opened based on configuration ipv4: %s, ipv6: %s"
                % (res["ipv4"], res["ipv6"])
            )
            return res
        self.port_opened = {}
        if self.ui_server:
            self.ui_server.updateWebsocket()
        if "ipv6" in self.supported_ip_types:
            res_ipv6_thread = self.spawn(
                self.portchecker.portCheck, self.port, "ipv6"
            )
        else:
            res_ipv6_thread = None
        res_ipv4 = self.portchecker.portCheck(self.port, "ipv4")
        if not res_ipv4["opened"] and config.tor != "always":
            if self.portchecker.portOpen(self.port):
                res_ipv4 = self.portchecker.portCheck(self.port, "ipv4")
        if res_ipv6_thread is None:
            res_ipv6 = {"ip": None, "opened": None}
        else:
            res_ipv6 = res_ipv6_thread.get()
            if (
                res_ipv6["opened"]
                and not self.getIpType(res_ipv6["ip"]) == "ipv6"
            ):
                log.info(
                    "Invalid IPv6 address from port check: %s" % res_ipv6["ip"]
                )
                res_ipv6["opened"] = False
        self.ip_external_list = []
        for res_ip in [res_ipv4, res_ipv6]:
            if res_ip["ip"] and res_ip["ip"] not in self.ip_external_list:
                self.ip_external_list.append(res_ip["ip"])
                SiteManager.peer_blacklist.append((res_ip["ip"], self.port))
        log.info(
            "Server port opened ipv4: %s, ipv6: %s"
            % (res_ipv4["opened"], res_ipv6["opened"])
        )
        res = {"ipv4": res_ipv4["opened"], "ipv6": res_ipv6["opened"]}
        interface_ips = helper.getInterfaceIps("ipv4")
        if "ipv6" in self.supported_ip_types:
            interface_ips += helper.getInterfaceIps("ipv6")
        for ip in interface_ips:
            if not helper.isPrivateIp(ip) and ip not in self.ip_external_list:
                self.ip_external_list.append(ip)
                res[self.getIpType(ip)] = True
                SiteManager.peer_blacklist.append((ip, self.port))
                log.debug("External ip found on interfaces: %s" % ip)
        self.port_opened.update(res)
        if self.ui_server:
            self.ui_server.updateWebsocket()
        return res

    @util.Noparallel(queue=True)
    def recheckPort(self):
        if self.recheck_port:
            self.portCheck()
            self.recheck_port = False

    @util.Noparallel()
    def waitForInternetOnline(self):
        if self.isOfflineMode() or self.stopping:
            return None
        if self.isInternetOnline():
            return False
        while not self.isInternetOnline():
            self.sleep(30)
            if self.isOfflineMode() or self.stopping:
                return None
            if self.isInternetOnline():
                break
            if len(self.update_pool) == 0:
                log.info(
                    "Internet connection seems to be broken. Running an update"
                    " for a random site to check if we are able to connect to"
                    " any peer."
                )
                thread = self.thread_pool.spawn(self.updateRandomSite)
                thread.join()
        self.recheckPort()
        return True

    def updateRandomSite(self, site_addresses=None, force=False):
        if not site_addresses:
            site_addresses = self.getSiteAddresses()
        site_addresses = random.sample(site_addresses, 1)
        if len(site_addresses) < 1:
            return
        address = site_addresses[0]
        site = self.getSite(address)
        if not site:
            return
        log.info("Randomly chosen site: %s", site.address_short)
        self.spawnUpdateSite(site).join()

    def updateSite(self, site, check_files=False, verify_files=False):
        if not site:
            return
        if verify_files:
            mode = "verify"
        elif check_files:
            mode = "check"
        else:
            mode = "update"
        log.info("running <%s> for %s" % (mode, site.address_short))
        site.update2(check_files=check_files, verify_files=verify_files)

    def spawnUpdateSite(self, site, check_files=False, verify_files=False):
        fake_thread = FakeThread()
        self.update_threads[site.address] = fake_thread
        thread = self.update_pool.spawn(
            self.updateSite,
            site,
            check_files=check_files,
            verify_files=verify_files,
        )
        self.update_threads[site.address] = thread
        return thread

    def lookupInUpdatePool(self, site_address):
        thread = self.update_threads.get(site_address, None)
        if not thread or thread.ready():
            return None
        return thread

    def siteIsInUpdatePool(self, site_address):
        return self.lookupInUpdatePool(site_address) is not None

    def invalidateUpdateTime(self, invalid_interval):
        for address in self.getSiteAddresses():
            site = self.getSite(address)
            if site:
                site.invalidateUpdateTime(invalid_interval)

    def isSiteUpdateTimeValid(self, site_address):
        site = self.getSite(site_address)
        if not site:
            return False
        return site.isUpdateTimeValid()

    def updateSites(self):
        task_nr = self.update_sites_task_next_nr
        self.update_sites_task_next_nr += 1
        task_description = "updateSites [#%d]" % task_nr
        log.info("%s: started", task_description)
        if len(self.getSites()) <= 2:
            for address, site in list(self.getSites().items()):
                self.updateSite(site, check_files=True)
        self.recheckPort()
        all_site_addresses = self.getSiteAddresses()
        site_addresses = [
            address
            for address in all_site_addresses
            if not self.isSiteUpdateTimeValid(address)
        ]
        log.info(
            "%s: chosen %d sites (of %d)",
            task_description,
            len(site_addresses),
            len(all_site_addresses),
        )
        sites_processed = 0
        sites_skipped = 0
        start_time = time.time()
        self.update_start_time = start_time
        progress_print_time = time.time()
        for site_address in site_addresses:
            site = None
            self.sleep(1)
            self.waitForInternetOnline()
            while self.isActiveMode() and self.shouldThrottleNewConnections():
                self.sleep(1)
            if not self.isActiveMode():
                break
            site = self.getSite(site_address)
            if (
                not site
                or site.isUpdateTimeValid()
                or self.siteIsInUpdatePool(site_address)
            ):
                sites_skipped += 1
                continue
            sites_processed += 1
            thread = self.spawnUpdateSite(site)
            if not self.isActiveMode():
                break
            if time.time() - progress_print_time > 60:
                progress_print_time = time.time()
                time_spent = time.time() - start_time
                time_per_site = time_spent / float(sites_processed)
                sites_left = len(site_addresses) - sites_processed
                time_left = time_per_site * sites_left
                log.info(
                    (
                        "%s: DONE: %d sites in %.2fs (%.2fs per site);"
                        " SKIPPED: %d sites; LEFT: %d sites in %.2fs"
                    ),
                    task_description,
                    sites_processed,
                    time_spent,
                    time_per_site,
                    sites_skipped,
                    sites_left,
                    time_left,
                )
        if not self.isActiveMode():
            log.info("%s: stopped", task_description)
        else:
            log.info(
                "%s: finished in %.2fs",
                task_description,
                time.time() - start_time,
            )

    def peekSiteForVerification(self):
        check_files_interval = 60 * 60 * 24
        verify_files_interval = 60 * 60 * 24 * 10
        site_addresses = self.getSiteAddresses()
        random.shuffle(site_addresses)
        for site_address in site_addresses:
            site = self.getSite(site_address)
            if not site:
                continue
            mode = site.isFileVerificationExpired(
                check_files_interval, verify_files_interval
            )
            if mode:
                return site_address, mode
        return None, None

    def sitesVerificationThread(self):
        log.info("sitesVerificationThread started")
        short_timeout = 20
        long_timeout = 120
        self.sleep(long_timeout)
        while self.isActiveMode():
            site = None
            self.sleep(short_timeout)
            self.waitForInternetOnline()
            while self.isActiveMode() and self.shouldThrottleNewConnections():
                self.sleep(1)
            if not self.isActiveMode():
                break
            site_address, mode = self.peekSiteForVerification()
            if not site_address:
                self.sleep(long_timeout)
                continue
            while (
                self.siteIsInUpdatePool(site_address) and self.isActiveMode()
            ):
                self.sleep(1)
            if not self.isActiveMode():
                break
            site = self.getSite(site_address)
            if not site:
                continue
            if mode == "verify":
                check_files = False
                verify_files = True
            elif mode == "check":
                check_files = True
                verify_files = False
            else:
                continue
            thread = self.spawnUpdateSite(
                site, check_files=check_files, verify_files=verify_files
            )
        log.info("sitesVerificationThread stopped")

    def sitesMaintenanceThread(self, mode="full"):
        log.info("sitesMaintenanceThread(%s) started" % mode)
        startup = True
        short_timeout = 2
        min_long_timeout = 10
        max_long_timeout = 60 * 10
        long_timeout = min_long_timeout
        short_cycle_time_limit = 60 * 2
        while self.isActiveMode():
            self.sleep(long_timeout)
            while self.isActiveMode() and self.shouldThrottleNewConnections():
                self.sleep(1)
            if not self.isActiveMode():
                break
            start_time = time.time()
            log.debug(
                "Starting <%s> maintenance cycle: connections=%s, internet=%s",
                mode,
                len(self.connections),
                self.isInternetOnline(),
            )
            start_time = time.time()
            site_addresses = self.getSiteAddresses()
            sites_processed = 0
            for site_address in site_addresses:
                if not self.isActiveMode():
                    break
                site = self.getSite(site_address)
                if not site:
                    continue
                log.debug(
                    "Running maintenance for site: %s", site.address_short
                )
                done = site.runPeriodicMaintenance(startup=startup)
                site = None
                if done:
                    sites_processed += 1
                    self.sleep(short_timeout)
                if (
                    mode == "short"
                    and time.time() - start_time > short_cycle_time_limit
                ):
                    break
            log.debug(
                (
                    "<%s> maintenance cycle finished in %.2fs. Total sites:"
                    " %d. Processed sites: %d. Timeout: %d"
                ),
                mode,
                time.time() - start_time,
                len(site_addresses),
                sites_processed,
                long_timeout,
            )
            if sites_processed:
                long_timeout = max(int(long_timeout / 2), min_long_timeout)
            else:
                long_timeout = min(long_timeout + 1, max_long_timeout)
            site_addresses = None
            startup = False
        log.info("sitesMaintenanceThread(%s) stopped" % mode)

    def keepAliveThread(self):
        log.info("keepAliveThread started")
        while self.isActiveMode():
            self.waitForInternetOnline()
            threshold = self.internet_outage_threshold / 2.0
            self.sleep(threshold / 2.0)
            while self.isActiveMode() and self.shouldThrottleNewConnections():
                self.sleep(1)
            if not self.isActiveMode():
                break
            last_activity_time = max(
                self.last_successful_internet_activity_time,
                self.last_outgoing_internet_activity_time,
            )
            now = time.time()
            if not len(self.getSites()):
                continue
            if last_activity_time > now - threshold:
                continue
            if len(self.update_pool) != 0:
                continue
            log.info(
                (
                    "No network activity for %.2fs. Running an update for a"
                    " random site."
                ),
                now - last_activity_time,
            )
            self.update_pool.spawn(self.updateRandomSite, force=True)
        log.info("keepAliveThread stopped")

    def reloadTrackerFilesThread(self):
        log.info("reloadTrackerFilesThread started")
        interval = 60 * 10
        while self.isActiveMode():
            self.sleep(interval)
            if not self.isActiveMode():
                break
            config.loadTrackersFile()
        log.info("reloadTrackerFilesThread stopped")

    def wakeupWatcherThread(self):
        log.info("wakeupWatcherThread started")
        last_time = time.time()
        last_my_ips = socket.gethostbyname_ex("")[2]
        while self.isActiveMode():
            self.sleep(30)
            if not self.isActiveMode():
                break
            is_time_changed = (
                time.time() - max(self.last_request, last_time) > 60 * 3
            )
            if is_time_changed:
                log.info(
                    "Wakeup detected: time warp from %0.f to %0.f (%0.f sleep"
                    " seconds), acting like startup…"
                    % (last_time, time.time(), time.time() - last_time)
                )
            my_ips = socket.gethostbyname_ex("")[2]
            is_ip_changed = my_ips != last_my_ips
            if is_ip_changed:
                log.info(
                    "IP change detected from %s to %s" % (last_my_ips, my_ips)
                )
            if is_time_changed or is_ip_changed:
                invalid_interval = (
                    last_time
                    - self.internet_outage_threshold
                    - random.randint(60 * 5, 60 * 10),
                    time.time(),
                )
                self.invalidateUpdateTime(invalid_interval)
                self.recheck_port = True
                self.spawn(self.updateSites)
            last_time = time.time()
            last_my_ips = my_ips
        log.info("wakeupWatcherThread stopped")

    def setOfflineMode(self, offline_mode):
        ConnectionServer.setOfflineMode(self, offline_mode)
        self.setupActiveMode()

    def setPassiveMode(self, passive_mode):
        if self.passive_mode == passive_mode:
            return
        self.passive_mode = passive_mode
        if self.passive_mode:
            log.info("passive mode is ON")
        else:
            log.info("passive mode is OFF")
        self.setupActiveMode()

    def isPassiveMode(self):
        return self.passive_mode

    def setupActiveMode(self):
        active_mode = (not self.passive_mode) and (not self.isOfflineMode())
        if self.active_mode == active_mode:
            return
        self.active_mode = active_mode
        if self.active_mode:
            log.info("active mode is ON")
            self.enterActiveMode()
        else:
            log.info("active mode is OFF")
            self.leaveActiveMode()

    def killActiveModeThreads(self):
        for key, thread in list(self.active_mode_threads.items()):
            if thread:
                if not thread.ready():
                    log.info("killing %s" % key)
                    gevent.kill(thread)
                del self.active_mode_threads[key]

    def leaveActiveMode(self):
        pass

    def enterActiveMode(self):
        self.killActiveModeThreads()
        x = self.active_mode_threads
        p = self.active_mode_thread_pool
        x["thread_keep_alive"] = p.spawn(self.keepAliveThread)
        x["thread_wakeup_watcher"] = p.spawn(self.wakeupWatcherThread)
        x["thread_sites_verification"] = p.spawn(self.sitesVerificationThread)
        x["thread_reload_tracker_files"] = p.spawn(
            self.reloadTrackerFilesThread
        )
        x["thread_sites_maintenance_full"] = p.spawn(
            self.sitesMaintenanceThread, mode="full"
        )
        x["thread_sites_maintenance_short"] = p.spawn(
            self.sitesMaintenanceThread, mode="short"
        )
        x["thread_initial_site_updater"] = p.spawn(self.updateSites)

    def isActiveMode(self):
        self.setupActiveMode()
        if not self.active_mode:
            return False
        if not self.running:
            return False
        if self.stopping:
            return False
        return True

    def start(
        self, passive_mode=False, check_sites=None, check_connections=True
    ):
        if check_sites is not None:
            passive_mode = not check_sites
        if self.stopping:
            return False
        ConnectionServer.start(self, check_connections=check_connections)
        try:
            self.stream_server.start()
        except Exception as err:
            log.error(
                "Error listening on: %s:%s: %s" % (self.ip, self.port, err)
            )
        if config.debug:
            from Debug import DebugReloader

            DebugReloader.watcher.addCallback(self.reload)
        self.getSites()
        self.setPassiveMode(passive_mode)
        ConnectionServer.listen(self)
        log.info("Stopped.")

    def stop(self, ui_websocket=None):
        if self.running and self.portchecker.upnp_port_opened:
            log.debug("Closing port %d" % self.port)
            try:
                self.portchecker.portClose(self.port)
                log.info("Closed port via upnp.")
            except Exception as err:
                log.info(
                    "Failed at attempt to use upnp to close port: %s" % err
                )
        return ConnectionServer.stop(self, ui_websocket=ui_websocket)
