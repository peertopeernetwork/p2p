from Config import config
from Plugin import PluginManager

allow_reload = False


@PluginManager.registerTo("UserManager")
class UserManagerPlugin(object):
    def load(self):
        if not config.multiuser_local:
            if not self.users:
                self.users = {}
            return self.users
        else:
            return super(UserManagerPlugin, self).load()

    def get(self, master_address=None):
        users = self.list()
        if master_address in users:
            user = users[master_address]
        else:
            user = None
        return user


@PluginManager.registerTo("User")
class UserPlugin(object):
    def save(self):
        if not config.multiuser_local:
            return False
        else:
            return super(UserPlugin, self).save()
