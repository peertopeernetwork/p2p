import logging, json, os, re, sys, time, socket
from Plugin import PluginManager
from Config import config
from Debug import Debug
from http.client import HTTPSConnection, HTTPConnection, HTTPException
from base64 import b64encode

allow_reload = False


@PluginManager.registerTo("SiteManager")
class SiteManagerPlugin(object):
    def load(self, *args, **kwargs):
        super(SiteManagerPlugin, self).load(*args, **kwargs)
        self.log = logging.getLogger("BitDNSLocal Plugin")
        self.error_message = None
        if (
            not config.namecoin_host
            or not config.namecoin_rpcport
            or not config.namecoin_rpcuser
            or not config.namecoin_rpcpassword
        ):
            self.error_message = "Missing parameters"
            self.log.error(
                "Missing parameters to connect to Namecoin node. Please check"
                " all the arguments needed with '--help'. Peer-to-Peer Network"
                " will continue working without it."
            )
            return
        url = "%(host)s:%(port)s" % {
            "host": config.namecoin_host,
            "port": config.namecoin_rpcport,
        }
        self.c = HTTPConnection(url, timeout=3)
        user_pass = "%(user)s:%(password)s" % {
            "user": config.namecoin_rpcuser,
            "password": config.namecoin_rpcpassword,
        }
        userAndPass = b64encode(bytes(user_pass, "utf-8")).decode("ascii")
        self.headers = {
            "Authorization": "Basic %s" % userAndPass,
            "Content-Type": " application/json ",
        }
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": "p2p", "method": "ping", "params": []}
        )
        try:
            self.c.request("POST", "/", payload, headers=self.headers)
            response = self.c.getresponse()
            data = response.read()
            self.c.close()
            if response.status == 200:
                result = json.loads(data.decode())["result"]
            else:
                raise Exception(response.reason)
        except Exception as err:
            self.log.error(
                "The Namecoin node is unreachable. Please check the"
                " configuration value are correct. Peer-to-Peer Network will"
                " continue working without it."
            )
            self.error_message = err
        self.cache = dict()

    def isAddress(self, address):
        return self.isBitDomain(address) or super(
            SiteManagerPlugin, self
        ).isAddress(address)

    def isDomain(self, address):
        return self.isBitDomain(address) or super(
            SiteManagerPlugin, self
        ).isDomain(address)

    def isBitDomain(self, address):
        return re.match(r"(.*?)([A-Za-z0-9_-]+\.bit)$", address)

    def get(self, address):
        if self.isBitDomain(address):
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
            site = super(SiteManagerPlugin, self).get(address)
        return site

    def need(self, address, *args, **kwargs):
        if self.isBitDomain(address):
            address_resolved = self.resolveDomain(address)
            if address_resolved:
                address = address_resolved
            else:
                return None
        return super(SiteManagerPlugin, self).need(address, *args, **kwargs)

    def resolveDomain(self, domain):
        domain = domain.lower()
        if domain[-4:] == ".bit":
            domain = domain[0:-4]
        domain_array = domain.split(".")
        if self.error_message:
            self.log.error(
                "Not able to connect to Namecoin node : {!s}".format(
                    self.error_message
                )
            )
            return None
        if len(domain_array) > 2:
            self.log.error(
                "Too many subdomains! Can only handle one level (eg."
                " staging.mixtape.bit)"
            )
            return None
        subdomain = ""
        if len(domain_array) == 1:
            domain = domain_array[0]
        else:
            subdomain = domain_array[0]
            domain = domain_array[1]
        if domain in self.cache:
            delta = time.time() - self.cache[domain]["time"]
            if delta < 3600:
                return self.cache[domain]["addresses_resolved"][subdomain]
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "p2p",
                "method": "name_show",
                "params": ["./" + domain],
            }
        )
        try:
            self.c.request("POST", "/", payload, headers=self.headers)
            response = self.c.getresponse()
            data = response.read()
            self.c.close()
            domain_object = json.loads(data.decode())["result"]
        except Exception as err:
            return None
        if "p2p" in domain_object["value"]:
            p2p_domains = json.loads(domain_object["value"])["p2p"]
            if isinstance(p2p_domains, str):
                p2p_domains = {"": p2p_domains}
            self.cache[domain] = {
                "addresses_resolved": p2p_domains,
                "time": time.time(),
            }
        elif "map" in domain_object["value"]:
            data_map = json.loads(domain_object["value"])["map"]
            p2p_domains = dict()
            for subdomain in data_map:
                if "p2p" in data_map[subdomain]:
                    p2p_domains[subdomain] = data_map[subdomain]["p2p"]
            if "p2p" in data_map and isinstance(data_map["p2p"], str):
                p2p_domains[""] = data_map["p2p"]
            self.cache[domain] = {
                "addresses_resolved": p2p_domains,
                "time": time.time(),
            }
        else:
            return None
        return self.cache[domain]["addresses_resolved"][subdomain]


@PluginManager.registerTo("ConfigPlugin")
class ConfigPlugin(object):
    def createArguments(self):
        group = self.parser.add_argument_group("BitDNS Local plugin")
        group.add_argument(
            "--namecoin_host", help="Host to Namecoin node (eg. 127.0.0.1)"
        )
        group.add_argument(
            "--namecoin_rpcport", help="Port to connect (eg. 8336)"
        )
        group.add_argument(
            "--namecoin_rpcuser",
            help="RPC user to connect to the Namecoin node (eg. user)",
        )
        group.add_argument(
            "--namecoin_rpcpassword",
            help="RPC password to connect to Namecoin node",
        )
        return super(ConfigPlugin, self).createArguments()
