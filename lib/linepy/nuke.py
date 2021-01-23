# -*- coding: utf-8 -*-

def loggedIn(func):
    def checkLogin(*args, **kwargs):
        if args[0].isLogin:
            return func(*args, **kwargs)
        else:
            args[0].callback.other('You must login to LINE')
    return checkLogin
    
class Nuke(object):
    isLogin = False

    def __init__(self):
        self.isLogin = True

    def kickSerialized(self, gid, uid):
        data = '\x82!\x00\x10kickoutFromGroup\x15\x00\x18!%s\x19\x18!%s\x00' % (gid, uid)
        return self.nuke.flush_single(data.encode('raw_unicode_escape'))

    def sendMessageSerialized(self,gid,text):
        data = '\x82!\x00\x0bsendMessage\x15\x00\x1c(!%s\x88\x05%s\x00\x00' %(gid,text)
        return self.nuke.flush_single(data.encode('raw_unicode_escape'))

    def acceptGroupInvitationSerialized(self, gid, ticket):
        data = "\x82!\x00\x1dacceptGroupInvitationByTicket\x15\x00\x18!%s\x18\n%s\x00" % (gid, ticket)
        return self.nuke.flush_single(data.encode('raw_unicode_escape'))

    def kickallSerialized(self, gid, uids):
        data = []
        for uid in uids:
            d = '\x82!\x00\x10kickoutFromGroup\x15\x00\x18!%s\x19\x18!%s\x00' % (gid, uid)
            data.append(d.encode())
        self.LineTransport_nuke.flush_multi(data)

    def inviteSerialized(self, gid, uids):
        stuff = "!".join(uids)
        data = '\x82!\x00\x0finviteIntoGroup\x15\x00\x18!%s\x19X!%s\x00' % (gid, stuff)
        return self.nuke.flush_single(data.encode())

    def cancelSerialized(self, gid, uids):
        stuff = "!".join(uids)
        data = '\x82!\x00\x0fcancelGroupInvitation\x15\x00\x18!%s\x19X!%s\x00' % (gid, stuff)
        return self.nuke.flush_single(data.encode('latin-1'))

    def rejectSerialized(self, gid):
        data = '\x82!\x00\x15rejectGroupInvitation\x15\x00\x18\x04%s\x00' % gid
        return self.nuke.flush_single(data.encode())

    def opxSerialized(self, to):
        data = '\x82!\x00\x0bsendMessage\x15\x00\x1c(!%s\x88\x04test\x00\x00' % to
        return self.nuke.flush_single(data.encode('latin-1'))

    def acceptSerialized(self, gid):
        #data = '\x82!\x00\x15acceptGroupInvitation\x15\x00\x18\x04%s\x00' % gid
        data = '\x82!\x00\x15acceptGroupInvitation\x15\x00\x18!%s\x00' % gid
        return self.nuke.flush_single(data.encode())

    def counterInvitation(self, gid, string):
        string = string.replace("\x1e", "!")
        data = '\x82!\x00\x0fcancelGroupInvitation\x15\x00\x18!%s\x19X!%s\x00' % (gid, string)
        return self.nuke.flush_single(data.encode())
