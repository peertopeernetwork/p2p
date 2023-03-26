import json
import logging
import re
import os
import time
import atexit
import collections
import gevent
import util
from Plugin import PluginManager
from Content import ContentDb
from Config import config
from util import helper
from util import RateLimit
from util import Cached


@PluginManager.acceptPlugins
class SiteManager(object):
    def __init__(self):
        self.log = logging.getLogger("SiteManager")
        self.log.debug("SiteManager created.")
        self.sites = {}
        self.sites_changed = int(time.time())
        self.loaded = False
        gevent.spawn(self.saveTimer)
        atexit.register(lambda: self.save(recalculate_size=True))
        self.send_back_lru = collections.OrderedDict()

    @util.Noparallel()
    def load(self, cleanup=True, startup=False):
        from Debug import Debug

        self.log.info(
            "Loading sites… (cleanup: %s, startup: %s)" % (cleanup, startup)
        )
        self.loaded = False
        from .Site import Site

        address_found = []
        added = 0
        load_s = time.time()
        try:
            json_path = "%s/sites.json" % config.data_dir
            data = json.load(open(json_path))
        except Exception as err:
            raise Exception("Unable to load %s: %s" % (json_path, err))
        sites_need = []
        for address, settings in data.items():
            if address not in self.sites:
                if os.path.isfile(
                    "%s/%s/content.json" % (config.data_dir, address)
                ):
                    s = time.time()
                    try:
                        site = Site(address, settings=settings)
                        site.content_manager.contents.get("content.json")
                    except Exception as err:
                        self.log.debug(
                            "Error loading site %s: %s" % (address, err)
                        )
                        continue
                    self.sites[address] = site
                    self.log.debug(
                        "Loaded site %s in %.3fs" % (address, time.time() - s)
                    )
                    added += 1
                elif startup:
                    self.log.debug(
                        "Found new site in sites.json: %s" % address
                    )
                    sites_need.append([address, settings])
                    added += 1
            address_found.append(address)
        if cleanup:
            for address in list(self.sites.keys()):
                if address not in address_found:
                    del self.sites[address]
                    self.log.debug("Removed site: %s" % address)
            content_db = ContentDb.getContentDb()
            for row in content_db.execute("SELECT * FROM site").fetchall():
                address = row["address"]
                if address not in self.sites and address not in address_found:
                    self.log.info(
                        "Deleting orphan site from content.db: %s" % address
                    )
                    try:
                        content_db.execute(
                            "DELETE FROM site WHERE ?", {"address": address}
                        )
                    except Exception as err:
                        self.log.error(
                            "Can't delete site %s from content_db: %s"
                            % (address, err)
                        )
                    if address in content_db.site_ids:
                        del content_db.site_ids[address]
                    if address in content_db.sites:
                        del content_db.sites[address]
        self.loaded = True
        for address, settings in sites_need:
            gevent.spawn(self.need, address, settings=settings)
        if added:
            self.log.info(
                "Added %s sites in %.3fs" % (added, time.time() - load_s)
            )

    def saveDelayed(self):
        RateLimit.callAsync("Save sites.json", allowed_again=5, func=self.save)

    def save(self, recalculate_size=False):
        if not self.sites:
            self.log.debug("Save skipped: No sites found")
            return
        if not self.loaded:
            self.log.debug("Save skipped: Not loaded")
            return
        s = time.time()
        data = {}
        s = time.time()
        for address, site in list(self.list().items()):
            if recalculate_size:
                (
                    site.settings["size"],
                    site.settings["size_optional"],
                ) = site.content_manager.getTotalSize()
            data[address] = site.settings
            data[address]["cache"] = site.getSettingsCache()
        time_generate = time.time() - s
        s = time.time()
        if data:
            helper.atomicWrite(
                "%s/sites.json" % config.data_dir,
                helper.jsonDumps(data).encode("utf_8"),
            )
        else:
            self.log.debug("Save error: No data")
        time_write = time.time() - s
        for address, site in self.list().items():
            site.settings["cache"] = {}
        self.log.debug(
            "Saved sites in %.2fs (generate: %.2fs, write: %.2fs)"
            % (time.time() - s, time_generate, time_write)
        )

    def saveTimer(self):
        while 1:
            time.sleep(60 * 10)
            self.save(recalculate_size=True)

    def isAddress(self, address):
        return re.match("^[A-Za-z0-9]{26,35}$", address)

    def isDomain(self, address):
        return False

    @Cached(timeout=10)
    def isDomainCached(self, address):
        return self.isDomain(address)

    def resolveDomain(self, domain):
        return False

    @Cached(timeout=10)
    def resolveDomainCached(self, domain):
        return self.resolveDomain(domain)

    def isAddressBlocked(self, address):
        return False

    def get(self, address):
        if self.isDomainCached(address):
            address_resolved = self.resolveDomainCached(address)
            if address_resolved:
                address = address_resolved
        if not self.loaded:
            self.log.debug("Loading site: %s)…" % address)
            self.load()
        site = self.sites.get(address)
        return site

    def add(self, address, all_file=True, settings=None, **kwargs):
        from .Site import Site

        self.sites_changed = int(time.time())
        for recover_address, recover_site in list(self.sites.items()):
            if recover_address.lower() == address.lower():
                return recover_site
        if not self.isAddress(address):
            return False
        self.log.debug("Added new site: %s" % address)
        config.loadTrackersFile()
        site = Site(address, settings=settings)
        self.sites[address] = site
        if not site.settings["serving"]:
            site.settings["serving"] = True
        site.saveSettings()
        if all_file:
            site.download(check_size=True, blind_includes=True)
        return site

    def need(self, address, *args, **kwargs):
        if self.isDomainCached(address):
            address_resolved = self.resolveDomainCached(address)
            if address_resolved:
                address = address_resolved
        site = self.get(address)
        if not site:
            site = self.add(address, *args, **kwargs)
        return site

    def delete(self, address):
        self.sites_changed = int(time.time())
        self.log.debug("Deleted site: %s" % address)
        del self.sites[address]
        self.save()

    def list(self):
        if not self.loaded:
            self.log.debug("Sites not loaded yet…")
            self.load(startup=True)
        return self.sites

    def checkSendBackLRU(self, site, peer, inner_path, remote_modified):
        key = site.address + " - " + peer.key + " - " + inner_path
        sent_modified = self.send_back_lru.get(key, 0)
        return remote_modified < sent_modified

    def addToSendBackLRU(self, site, peer, inner_path, modified):
        key = site.address + " - " + peer.key + " - " + inner_path
        if self.send_back_lru.get(key, None) is None:
            self.send_back_lru[key] = modified
            while len(self.send_back_lru) > config.send_back_lru_size:
                self.send_back_lru.popitem(last=False)
        else:
            self.send_back_lru.move_to_end(key, last=True)


site_manager = SiteManager()
if config.action == "main":
    peer_blacklist = [
        ("127.0.0.1", config.fileserver_port),
        ("::1", config.fileserver_port),
    ]
else:
    peer_blacklist = []
