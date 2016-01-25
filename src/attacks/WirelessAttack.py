import src.settings as settings


class WirelessAttack(object):
    """ Sort of guide template for the format of objects.
    check() will be called to see if the attack is doable
    perform() will be the attack itself
    """

    def __init__(self):
        self.interface = settings.INTERFACE

    def check(self):
        raise NotImplementedError

    def perform(self):
        raise NotImplementedError
