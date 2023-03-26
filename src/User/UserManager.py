import json
import logging
import time
from .User import User
from Plugin import PluginManager
from Config import config


@PluginManager.acceptPlugins
class UserManager(object):
    def __init__(self):
        self.users = {}
        self.log = logging.getLogger("UserManager")

    def load(self):
        if not self.users:
            self.users = {}
        user_found = []
        added = 0
        s = time.time()
        try:
            json_path = "%s/users.json" % config.data_dir
            data = json.load(open(json_path))
        except Exception as err:
            raise Exception("Unable to load %s: %s" % (json_path, err))
        for master_address, data in list(data.items()):
            if master_address not in self.users:
                user = User(master_address, data=data)
                self.users[master_address] = user
                added += 1
            user_found.append(master_address)
        for master_address in list(self.users.keys()):
            if master_address not in user_found:
                del self.users[master_address]
                self.log.debug("Removed user: %s" % master_address)
        if added:
            self.log.debug(
                "Added %s users in %.3fs" % (added, time.time() - s)
            )

    def create(self, master_address=None, master_seed=None):
        self.list()
        user = User(master_address, master_seed)
        self.log.debug("Created user: %s" % user.master_address)
        if user.master_address:
            self.users[user.master_address] = user
            user.saveDelayed()
        return user

    def list(self):
        if self.users == {}:
            self.load()
        return self.users

    def get(self, master_address=None):
        users = self.list()
        if users:
            return list(users.values())[0]
        else:
            return None


user_manager = UserManager()
