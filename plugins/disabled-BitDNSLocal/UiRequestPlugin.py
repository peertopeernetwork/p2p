import re
from Plugin import PluginManager


@PluginManager.registerTo("UiRequest")
class UiRequestPlugin(object):
    def __init__(self, *args, **kwargs):
        from Site import SiteManager

        self.site_manager = SiteManager.site_manager
        super(UiRequestPlugin, self).__init__(*args, **kwargs)

    def actionSiteMedia(self, path):
        match = re.match(
            r"/media/(?P<address>[A-Za-z0-9-]+\.[A-Za-z0-9.-]+)(?P<inner_path>/.*|$)",
            path,
        )
        if match:
            domain = match.group("address")
            address = self.site_manager.resolveDomain(domain)
            if address:
                path = "/media/" + address + match.group("inner_path")
        return super(UiRequestPlugin, self).actionSiteMedia(path)

    def isMediaRequestAllowed(self, site_address, referer):
        referer_path = re.sub("http[s]{0,1}://.*?/", "/", referer).replace(
            "/media", ""
        )
        referer_path = re.sub(r"\?.*", "", referer_path)
        if self.isProxyRequest():
            referer = re.sub("^http://p2p[/]+", "http://", referer)
            referer_site_address = re.match(
                "http[s]{0,1}://(.*?)(/|$)", referer
            ).group(1)
        else:
            referer_site_address = re.match(
                r"/(?P<address>[A-Za-z0-9.-]+)(?P<inner_path>/.*|$)",
                referer_path,
            ).group("address")
        if referer_site_address == site_address:
            return True
        elif (
            self.site_manager.resolveDomain(referer_site_address)
            == site_address
        ):
            return True
        else:
            return False
