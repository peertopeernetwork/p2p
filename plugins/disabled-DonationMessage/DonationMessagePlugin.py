import re
from Plugin import PluginManager


@PluginManager.registerTo("UiRequest")
class UiRequestPlugin(object):
    def renderWrapper(self, *args, **kwargs):
        body = super(UiRequestPlugin, self).renderWrapper(*args, **kwargs)
        inject_html = """
            <style>
             #donation_message { position: absolute; bottom: 0px; right: 20px; padding: 7px; font-family: Arial; font-size: 11px }
            </style>
            <a id='donation_message' href='https://blockchain.info/address/1QDhxQ6PraUZa21ET5fYUCPgdrwBomnFgX' target='_blank'>Please donate to help to keep this Peer-to-Peer Network alive</a>.
            </body>
            </html>
        """
        return re.sub(r"</body>\s*</html>\s*$", inject_html, body)
