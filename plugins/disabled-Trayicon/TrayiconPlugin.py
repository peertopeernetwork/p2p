import os
import sys
import atexit

from Plugin import PluginManager
from Config import config
from Translate import Translate

allow_reload = False


plugin_dir = os.path.dirname(__file__)

if "_" not in locals():
    _ = Translate(plugin_dir + "/languages/")


@PluginManager.register_to("Actions")
class ActionsPlugin:
    def main(self):
        global notificationicon, winfolders
        from .lib import notificationicon, winfolders
        import gevent.threadpool
        import main

        self.main = main

        icon = notificationicon.NotificationIcon(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "trayicon.ico"
            ),
            "Peer-to-Peer Network %s" % config.version,
        )
        self.icon = icon

        self.console = False

        @atexit.register
        def hideIcon():
            try:
                icon.die()
            except Exception as err:
                print("Error removing trayicon: %s" % err)

        ui_ip = config.ui_ip if config.ui_ip != "*" else "127.0.0.1"

        if ":" in ui_ip:
            ui_ip = "[" + ui_ip + "]"

        icon.items = [
            (self.titleIp, False),
            (self.titleConnections, False),
            (self.titleTransfer, False),
            (self.titleConsole, self.toggleConsole),
            (self.titleAutorun, self.toggleAutorun),
            "--",
            (
                _["Peer-to-Peer Network Github"],
                lambda: self.opensite(
                    "https://github.com/peertopeernetwork/p2p"
                ),
            ),
            (
                _["Report bug/request feature"],
                lambda: self.opensite(
                    "https://github.com/peertopeernetwork/p2p/issues"
                ),
            ),
            "--",
            (
                _["!Open Peer-to-Peer Network"],
                lambda: self.opensite(
                    "http://%s:%s/%s"
                    % (ui_ip, config.ui_port, config.homepage)
                ),
            ),
            "--",
            (_["Quit"], self.quit),
        ]

        if not notificationicon.hasConsole():
            del icon.items[3]

        icon.clicked = lambda: self.opensite(
            "http://%s:%s/%s" % (ui_ip, config.ui_port, config.homepage)
        )
        self.quit_servers_event = gevent.threadpool.ThreadResult(
            lambda res: gevent.spawn_later(0.1, self.quitServers),
            gevent.threadpool.get_hub(),
            lambda: True,
        )
        gevent.threadpool.start_new_thread(icon._run, ())
        super().main()
        icon._die = True

    def quit(self):
        self.icon.die()
        self.quit_servers_event.set(True)

    def quitServers(self):
        self.main.ui_server.stop()
        self.main.file_server.stop()

    def opensite(self, url):
        import webbrowser

        webbrowser.open(url, new=0)

    def titleIp(self):
        title = "!IP: %s " % ", ".join(self.main.file_server.ip_external_list)
        if any(self.main.file_server.port_opened):
            title += _["(active)"]
        else:
            title += _["(passive)"]
        return title

    def titleConnections(self):
        title = _["Connections: %s"] % len(self.main.file_server.connections)
        return title

    def titleTransfer(self):
        title = _["Received: %.2f MB | Sent: %.2f MB"] % (
            float(self.main.file_server.bytes_recv) / 1024 / 1024,
            float(self.main.file_server.bytes_sent) / 1024 / 1024,
        )
        return title

    def titleConsole(self):
        translate = _["Show console window"]
        if self.console:
            return "+" + translate
        else:
            return translate

    def toggleConsole(self):
        if self.console:
            notificationicon.hideConsole()
            self.console = False
        else:
            notificationicon.showConsole()
            self.console = True

    def getAutorunPath(self):
        return "%s\\p2p.cmd" % winfolders.get(winfolders.STARTUP)

    def formatAutorun(self):
        args = sys.argv[:]

        if not getattr(sys, "frozen", False):
            args.insert(0, sys.executable)
            cwd = os.getcwd()
        else:
            cwd = os.path.dirname(sys.executable)

        ignored_args = [
            "--open_browser",
            "default_browser",
            "--dist_type",
            "bundle_win64",
        ]

        if sys.platform == "win32":
            args = [
                '"%s"' % arg for arg in args if arg and arg not in ignored_args
            ]
        cmd = " ".join(args)

        cmd = cmd.replace("start.py", "p2p.py").strip()
        cmd += ' --open_browser ""'

        return "\r\n".join(
            [
                "@echo off",
                "chcp 65001 > nul",
                "set PYTHONIOENCODING=utf-8",
                'cd /D "%s"' % cwd,
                'start "" %s' % cmd,
            ]
        )

    def isAutorunEnabled(self):
        path = self.getAutorunPath()
        return (
            os.path.isfile(path)
            and open(path, "rb").read().decode("utf_8") == self.formatAutorun()
        )

    def titleAutorun(self):
        translate = _["Start Peer-to-Peer Network when Windows starts"]
        if self.isAutorunEnabled():
            return "+" + translate
        else:
            return translate

    def toggleAutorun(self):
        if self.isAutorunEnabled():
            os.unlink(self.getAutorunPath())
        else:
            open(self.getAutorunPath(), "wb").write(
                self.formatAutorun().encode("utf_8")
            )
