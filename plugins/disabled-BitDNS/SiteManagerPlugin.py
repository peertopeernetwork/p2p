import logging
import re
import time
from Config import config
from Plugin import PluginManager

allow_reload = False
log = logging.getLogger("BitDNSPlugin")


@PluginManager.registerTo("SiteManager")
class SiteManagerPlugin(object):
    site_bitdns = None
    db_domains = {}
    db_domains_modified = None

    def load(self, *args, **kwargs):
        super(SiteManagerPlugin, self).load(*args, **kwargs)
        if not self.get(config.bit_resolver):
            self.need(config.bit_resolver)

    def isBitDomain(self, address):
        return re.match(r"(.*?)([A-Za-z0-9_-]+\.p2p)$", address)

    def resolveBitDomain(self, domain):
        domain = domain.lower()
        if not self.site_bitdns:
            self.site_bitdns = self.need(config.bit_resolver)
        site_bitdns_modified = self.site_bitdns.content_manager.contents.get(
            "content.json", {}
        ).get("modified", 0)
        if (
            not self.db_domains
            or self.db_domains_modified != site_bitdns_modified
        ):
            self.site_bitdns.needFile("data/names.json", priority=10)
            s = time.time()
            try:
                self.db_domains = self.site_bitdns.storage.loadJson(
                    "data/names.json"
                )
            except Exception as err:
                log.error("Error loading names.json: %s" % err)
            log.debug(
                "Domain db with %s entries loaded in %.3fs (modification: %s"
                " -> %s)"
                % (
                    len(self.db_domains),
                    time.time() - s,
                    self.db_domains_modified,
                    site_bitdns_modified,
                )
            )
            self.db_domains_modified = site_bitdns_modified
        return self.db_domains.get(domain)

    def resolveDomain(self, domain):
        return self.resolveBitDomain(domain) or super(
            SiteManagerPlugin, self
        ).resolveDomain(domain)

    def isDomain(self, address):
        return self.isBitDomain(address) or super(
            SiteManagerPlugin, self
        ).isDomain(address)


@PluginManager.registerTo("ConfigPlugin")
class ConfigPlugin(object):
    def createArguments(self):
        group = self.parser.add_argument_group("BitDNS plugin")
        group.add_argument(
            "--bit_resolver",
            help="Peer-to-Peer Network site to resolve .p2p domains",
            default="1UjqdKbyow9ubHQbzjULWKYXHf3vFVZ8W",
            metavar="address",
        )
        return super(ConfigPlugin, self).createArguments()
