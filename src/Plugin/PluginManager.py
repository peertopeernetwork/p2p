import logging
import os
import sys
import shutil
import time
from collections import defaultdict
import importlib
import json
from Debug import Debug
from Config import config
import plugins


class PluginManager:
    def __init__(self):
        self.log = logging.getLogger("PluginManager")
        self.path_plugins = os.path.abspath(os.path.dirname(plugins.__file__))
        self.path_installed_plugins = config.data_dir + "/__plugins__"
        self.plugins = defaultdict(list)
        self.subclass_order = {}
        self.pluggable = {}
        self.plugin_names = []
        self.plugins_updated = {}
        self.plugins_rev = {}
        self.after_load = []
        self.function_flags = {}
        self.reloading = False
        self.config_path = config.data_dir + "/plugins.json"
        self.loadConfig()
        self.config.setdefault("builtin", {})
        sys.path.append(os.path.join(os.getcwd(), self.path_plugins))
        self.migratePlugins()
        if config.debug:
            from Debug import DebugReloader

            DebugReloader.watcher.addCallback(self.reloadPlugins)

    def loadConfig(self):
        if os.path.isfile(self.config_path):
            try:
                self.config = json.load(
                    open(self.config_path, encoding="utf_8")
                )
            except Exception as err:
                self.log.error(
                    "Error loading %s: %s" % (self.config_path, err)
                )
                self.config = {}
        else:
            self.config = {}

    def saveConfig(self):
        f = open(self.config_path, "w", encoding="utf_8")
        json.dump(self.config, f, ensure_ascii=False, sort_keys=True, indent=2)

    def migratePlugins(self):
        for dir_name in os.listdir(self.path_plugins):
            if dir_name == "Mute":
                self.log.info(
                    "Deleting deprecated/renamed plugin: %s" % dir_name
                )
                shutil.rmtree("%s/%s" % (self.path_plugins, dir_name))

    def listPlugins(self, list_disabled=False):
        plugins = []
        for dir_name in sorted(os.listdir(self.path_plugins)):
            dir_path = os.path.join(self.path_plugins, dir_name)
            plugin_name = dir_name.replace("disabled-", "")
            if dir_name.startswith("disabled"):
                is_enabled = False
            else:
                is_enabled = True
            plugin_config = self.config["builtin"].get(plugin_name, {})
            if "enabled" in plugin_config:
                is_enabled = plugin_config["enabled"]
            if dir_name == "__pycache__" or not os.path.isdir(dir_path):
                continue
            if dir_name.startswith("Debug") and not config.debug:
                continue
            if not is_enabled and not list_disabled:
                continue
            plugin = {}
            plugin["source"] = "builtin"
            plugin["name"] = plugin_name
            plugin["dir_name"] = dir_name
            plugin["dir_path"] = dir_path
            plugin["inner_path"] = plugin_name
            plugin["enabled"] = is_enabled
            plugin["rev"] = config.rev
            plugin["loaded"] = plugin_name in self.plugin_names
            plugins.append(plugin)
        plugins += self.listInstalledPlugins(list_disabled)
        return plugins

    def listInstalledPlugins(self, list_disabled=False):
        plugins = []
        for address, site_plugins in sorted(self.config.items()):
            if address == "builtin":
                continue
            for plugin_inner_path, plugin_config in sorted(
                site_plugins.items()
            ):
                is_enabled = plugin_config.get("enabled", False)
                if not is_enabled and not list_disabled:
                    continue
                plugin_name = os.path.basename(plugin_inner_path)
                dir_path = "%s/%s/%s" % (
                    self.path_installed_plugins,
                    address,
                    plugin_inner_path,
                )
                plugin = {}
                plugin["source"] = address
                plugin["name"] = plugin_name
                plugin["dir_name"] = plugin_name
                plugin["dir_path"] = dir_path
                plugin["inner_path"] = plugin_inner_path
                plugin["enabled"] = is_enabled
                plugin["rev"] = plugin_config.get("rev", 0)
                plugin["loaded"] = plugin_name in self.plugin_names
                plugins.append(plugin)
        return plugins

    def loadPlugins(self):
        all_loaded = True
        s = time.time()
        for plugin in self.listPlugins():
            self.log.debug(
                "Loading plugin: %s (%s)" % (plugin["name"], plugin["source"])
            )
            if plugin["source"] != "builtin":
                self.plugins_rev[plugin["name"]] = plugin["rev"]
                site_plugin_dir = os.path.dirname(plugin["dir_path"])
                if site_plugin_dir not in sys.path:
                    sys.path.append(site_plugin_dir)
            try:
                sys.modules[plugin["name"]] = __import__(plugin["dir_name"])
            except Exception as err:
                self.log.error(
                    "Plugin %s load error: %s"
                    % (plugin["name"], Debug.formatException(err))
                )
                all_loaded = False
            if plugin["name"] not in self.plugin_names:
                self.plugin_names.append(plugin["name"])
        self.log.debug("Plugins loaded in %.3fs" % (time.time() - s))
        for func in self.after_load:
            func()
        return all_loaded

    def reloadPlugins(self):
        self.reloading = True
        self.after_load = []
        self.plugins_before = self.plugins
        self.plugins = defaultdict(list)
        for module_name, module in list(sys.modules.items()):
            if not module or not getattr(module, "__file__", None):
                continue
            if (
                self.path_plugins not in module.__file__
                and self.path_installed_plugins not in module.__file__
            ):
                continue
            if "allow_reload" in dir(module) and not module.allow_reload:
                for class_name, classes in self.plugins_before.items():
                    for c in classes:
                        if c.__module__ != module.__name__:
                            continue
                        self.plugins[class_name].append(c)
            else:
                try:
                    importlib.reload(module)
                except Exception as err:
                    self.log.error(
                        "Plugin %s reload error: %s"
                        % (module_name, Debug.formatException(err))
                    )
        self.loadPlugins()
        import gc

        patched = {}
        for class_name, classes in self.plugins.items():
            classes = classes[:]
            classes.reverse()
            base_class = self.pluggable[class_name]
            classes.append(base_class)
            pluginned_class = type(class_name, tuple(classes), dict())
            for obj in gc.get_objects():
                if type(obj).__name__ == class_name:
                    obj.__class__ = pluginned_class
                    patched[class_name] = patched.get(class_name, 0) + 1
        self.log.debug("Patched objects: %s" % patched)
        patched = {}
        for class_name, classes in self.plugins.items():
            for module_name, module in list(sys.modules.items()):
                if class_name in dir(module):
                    if "__class__" not in dir(getattr(module, class_name)):
                        continue
                    base_class = self.pluggable[class_name]
                    classes = self.plugins[class_name][:]
                    classes.reverse()
                    classes.append(base_class)
                    pluginned_class = type(class_name, tuple(classes), dict())
                    setattr(module, class_name, pluginned_class)
                    patched[class_name] = patched.get(class_name, 0) + 1
        self.log.debug("Patched modules: %s" % patched)
        self.reloading = False


plugin_manager = PluginManager()


def acceptPlugins(base_class):
    class_name = base_class.__name__
    plugin_manager.pluggable[class_name] = base_class
    if class_name in plugin_manager.plugins:
        classes = plugin_manager.plugins[class_name][:]
        if class_name in plugin_manager.subclass_order:
            classes = sorted(
                classes,
                key=lambda key: plugin_manager.subclass_order[
                    class_name
                ].index(str(key))
                if str(key) in plugin_manager.subclass_order[class_name]
                else 9999,
            )
        plugin_manager.subclass_order[class_name] = list(map(str, classes))
        classes.reverse()
        classes.append(base_class)
        plugined_class = type(class_name, tuple(classes), dict())
        plugin_manager.log.debug(
            "New class accepts plugins: %s (Loaded plugins: %s)"
            % (class_name, classes)
        )
    else:
        plugined_class = base_class
    return plugined_class


def registerTo(class_name):
    if config.debug and not plugin_manager.reloading:
        import gc

        for obj in gc.get_objects():
            if type(obj).__name__ == class_name:
                raise Exception(
                    "Class %s instances already present in memory" % class_name
                )
                break
    plugin_manager.log.debug("New plugin registered to: %s" % class_name)
    if class_name not in plugin_manager.plugins:
        plugin_manager.plugins[class_name] = []

    def classDecorator(self):
        plugin_manager.plugins[class_name].append(self)
        return self

    return classDecorator


def afterLoad(func):
    plugin_manager.after_load.append(func)
    return func


if __name__ == "__main__":

    @registerTo("Request")
    class RequestPlugin(object):
        def actionMainPage(self, path):
            return "Hello MainPage!"

    @acceptPlugins
    class Request(object):
        def route(self, path):
            func = getattr(self, "action" + path, None)
            if func:
                return func(path)
            else:
                return "Can't route to", path

    print(Request().route("MainPage"))
