# -*- coding: utf-8 -*-
from lib.akad.ttypes import Message
from .auth import Auth
from .models import Models
from .talk import Talk
from .timeline import Timeline
from .server import Server
from .shop import Shop
from .liff import Liff
from .callback import Callback

class LINE(Auth, Models, Talk, Timeline, Liff, Shop):

    def __init__(self, idOrAuthToken=None, passwd=None, **kwargs):
        self.certificate = None
        self.systemName = None
        self.appType = kwargs.pop('appType', None)
        self.appName = None
        self.showQr = None
        self.channelId = None
        self.keepLoggedIn = True
        self.customThrift = True
        self.certificate = kwargs.pop('certificate', None)
        callback = kwargs.pop("callback", None)
        Auth.__init__(self)
        self._e2ee = False
        if callback and callable(callback):
            self.callback = Callback(callback)
        if not (idOrAuthToken or idOrAuthToken and passwd):
            self.loginWithQrCode()
        if idOrAuthToken and passwd:
            self.loginWithCredential(idOrAuthToken, passwd)
        elif idOrAuthToken and not passwd:
            self.loginWithAuthToken(idOrAuthToken)
        self.__initAll()

    def __initAll(self):

        self.profile    = self.talk.getProfile()
        self.userTicket = self.generateUserTicket()
        self.groups     = self.talk.getGroupIdsJoined()
        self.friends    = self.talk.getAllContactIds()

        Models.__init__(self)
        Talk.__init__(self)
        Timeline.__init__(self)
        Liff.__init__(self)
        Shop.__init__(self)
