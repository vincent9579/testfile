# -*- coding: utf-8 -*-
from lib.thrift.transport.THttpClient import THttpClient
from lib.thrift.protocol.TCompactProtocol import TCompactProtocol
#from Lib.thrift.transport import THttpClient
from lib.akad import AuthService, TalkService, ChannelService, CallService, LiffService, ShopService
#from lib.akad import SecondaryQrCodeLoginService, SecondaryQrCodeLoginPermitNoticeService

class Session:

    def __init__(self, url, headers, path='', customThrift=False):
        self.host = url + path
        self.headers = headers
        self.customThrift = customThrift

    def Auth(self, isopen=True):
        self.transport = THttpClient(self.host)
#        self.trasnport = THttpClient.THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)
        
        self.protocol = TCompactProtocol(self.transport)
        self._auth  = AuthService.Client(self.protocol)
        
        if isopen:
            self.transport.open()

        return self._auth

    def Talk(self, isopen=True):
        self.transport = THttpClient(self.host)
#        self.transport = THttpClient.THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)
        
        self.protocol = TCompactProtocol(self.transport)
        self._talk  = TalkService.Client(self.protocol)
        
        if isopen:
            self.transport.open()

        return self._talk

#     def Secondary(self, isopen=True):
#         self.transport = THttpClient(self.host)
# #        self.transport = THttpClient.THttpClient(self.host)
#         self.transport.setCustomHeaders(self.headers)
        
#         self.protocol = TCompactProtocol(self.transport)
#         self._secondary  = SecondaryQrCodeLoginService.Client(self.protocol)
        
#         if isopen:
#             self.transport.open()

#         return self._secondary

#     def Secondary2(self, isopen=True):
#         self.transport = THttpClient(self.host)
# #        self.transport = THttpClient.THttpClient(self.host)
#         self.transport.setCustomHeaders(self.headers)
        
#         self.protocol = TCompactProtocol(self.transport)
#         self._secondary  = SecondaryQrCodeLoginPermitNoticeService.Client(self.protocol)
        
#         if isopen:
#             self.transport.open()

#         return self._secondary

    def Channel(self, isopen=True):
        self.transport = THttpClient(self.host)
#        self.transport = THttpClient.THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)

        self.protocol = TCompactProtocol(self.transport)
        self._channel  = ChannelService.Client(self.protocol)
        
        if isopen:
            self.transport.open()

        return self._channel

    def Call(self, isopen=True):
        self.transport = THttpClient(self.host)
#        self.transport = THttpClient.THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)

        self.protocol = TCompactProtocol(self.transport)
        self._call  = CallService.Client(self.protocol)
        
        if isopen:
            self.transport.open()

        return self._call
        
    def Liff(self, isopen=True):
        self.transport = THttpClient(self.host)
#        self.transport = THttpClient.THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)

        self.protocol = TCompactProtocol(self.transport)
        self._liff  = LiffService.Client(self.protocol)

        if isopen:
            self.transport.open()

        return self._liff

    def Shop(self, isopen=True):
        self.transport = THttpClient(self.host)
#        self.transport = THttpClient.THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)

        self.protocol = TCompactProtocol(self.transport)
        self._shop  = ShopService.Client(self.protocol)
        
        if isopen:
            self.transport.open()

        return self._shop

    def Liff(self, isopen=True):
        self.transport = THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)

        self.protocol = TCompactProtocol(self.transport)
        self._liff  = LiffService.Client(self.protocol)

        if isopen:
            self.transport.open()

        return self._liff

    def Nuke(self, isopen=True):
        self.nuke = THttpClient(self.host)
        self.nuke.setCustomHeaders(self.headers)

        if isopen:
            self.nuke.open()

        return self.nuke