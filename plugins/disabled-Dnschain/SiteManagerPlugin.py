import logging, json, os, re, sys, time
import gevent
from Plugin import PluginManager
from Config import config
from util import Http
from Debug import Debug

allow_reload = False
log = logging.getLogger("DnschainPlugin")


@PluginManager.registerTo("SiteManager")
class SiteManagerPlugin(object):
    dns_cache_path = "%s/dns_cache.json" % config.data_dir
    dns_cache = None

    def isAddress(self, address):
        if self.isDomain(address):
            return True
        else:
            return super(SiteManagerPlugin, self).isAddress(address)

    def isDomain(self, address):
        return re.match(r"(.*?)([A-Za-z0-9_-]+\.[A-Za-z0-9]+)$", address)

    def loadDnsCache(self):
        if os.path.isfile(self.dns_cache_path):
            self.dns_cache = json.load(open(self.dns_cache_path))
        else:
            self.dns_cache = {}
        log.debug("Loaded dns cache, entries: %s" % len(self.dns_cache))

    def saveDnsCache(self):
        json.dump(self.dns_cache, open(self.dns_cache_path, "wb"), indent=2)

    def resolveDomainDnschainNet(self, domain):
        try:
            match = self.isDomain(domain)
            sub_domain = match.group(1).strip(".")
            top_domain = match.group(2)
            if not sub_domain:
                sub_domain = "@"
            address = None
            with gevent.Timeout(5, Exception("Timeout: 5s")):
                res = Http.get(
                    "https://api.dnschain.net/v1/namecoin/key/%s" % top_domain
                ).read()
                data = json.loads(res)["data"]["value"]
                if "p2p" in data:
                    for key, val in data["p2p"].items():
                        self.dns_cache[key + "." + top_domain] = [
                            val,
                            time.time() + 60 * 60 * 5,
                        ]
                    self.saveDnsCache()
                    return data["p2p"].get(sub_domain)
            return address
        except Exception as err:
            log.debug(
                "Dnschain.net %s resolve error: %s"
                % (domain, Debug.formatException(err))
            )

    def resolveDomainDnschainInfo(self, domain):
        try:
            match = self.isDomain(domain)
            sub_domain = match.group(1).strip(".")
            top_domain = match.group(2)
            if not sub_domain:
                sub_domain = "@"
            address = None
            with gevent.Timeout(5, Exception("Timeout: 5s")):
                res = Http.get(
                    "https://dnschain.info/bit/d/%s"
                    % re.sub(r"\.bit$", "", top_domain)
                ).read()
                data = json.loads(res)["value"]
                for key, val in data["p2p"].items():
                    self.dns_cache[key + "." + top_domain] = [
                        val,
                        time.time() + 60 * 60 * 5,
                    ]
                self.saveDnsCache()
                return data["p2p"].get(sub_domain)
            return address
        except Exception as err:
            log.debug(
                "Dnschain.info %s resolve error: %s"
                % (domain, Debug.formatException(err))
            )

    def resolveDomain(self, domain):
        domain = domain.lower()
        if self.dns_cache is None:
            self.loadDnsCache()
        if domain.count(".") < 2:
            domain = "@." + domain
        domain_details = self.dns_cache.get(domain)
        if domain_details and time.time() < domain_details[1]:
            return domain_details[0]
        else:
            thread_dnschain_info = gevent.spawn(
                self.resolveDomainDnschainInfo, domain
            )
            thread_dnschain_net = gevent.spawn(
                self.resolveDomainDnschainNet, domain
            )
            gevent.joinall([thread_dnschain_net, thread_dnschain_info])
            if thread_dnschain_info.value and thread_dnschain_net.value:
                if thread_dnschain_info.value == thread_dnschain_net.value:
                    return thread_dnschain_info.value
                else:
                    log.error(
                        "Dns %s missmatch: %s != %s"
                        % (
                            domain,
                            thread_dnschain_info.value,
                            thread_dnschain_net.value,
                        )
                    )
            if domain_details:
                domain_details[1] = time.time() + 60 * 60
                return domain_details[0]
            else:
                self.dns_cache[domain] = [
                    None,
                    time.time() + 60,
                ]
                return None

    def need(self, address, all_file=True):
        if self.isDomain(address):
            address_resolved = self.resolveDomain(address)
            if address_resolved:
                address = address_resolved
            else:
                return None
        return super(SiteManagerPlugin, self).need(address, all_file)

    def get(self, address):
        if self.sites is None:
            self.load()
        if self.isDomain(address):
            address_resolved = self.resolveDomain(address)
            if address_resolved:
                site = self.sites.get(address_resolved)
                if site:
                    site_domain = site.settings.get("domain")
                    if site_domain != address:
                        site.settings["domain"] = address
            else:
                site = self.sites.get(address)
        else:
            site = self.sites.get(address)
        return site
