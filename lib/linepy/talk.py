# -*- coding: utf-8 -*-
from lib.akad.ttypes import *
from random import randint
from datetime import datetime, time, timedelta

import json, ntpath, requests, random, pytz

def loggedIn(func):
    def checkLogin(*args, **kwargs):
        if args[0].isLogin:
            return func(*args, **kwargs)
        else:
            args[0].callback.other('You want to call the function, you must login to LINE')
    return checkLogin

class Talk(object):
    isLogin = False
    _messageReq = {}
    _unsendMessageReq = 0

    def __init__(self):
        self.isLogin = True
        self.time = pytz.timezone('Asia/Jakarta')

    """User"""

    @loggedIn
    def acquireEncryptedAccessToken(self, featureType=2):
        return self.talk.acquireEncryptedAccessToken(featureType)

    @loggedIn
    def getProfile(self):
        return self.talk.getProfile()

    @loggedIn
    def getSettings(self):
        return self.talk.getSettings()

    @loggedIn
    def getUserTicket(self):
        return self.talk.getUserTicket()

    @loggedIn
    def generateUserTicket(self):
        try:
            ticket = self.getUserTicket().id
        except:
            self.reissueUserTicket()
            ticket = self.getUserTicket().id
        return ticket
    
    @loggedIn
    def acceptChatInvitationByTicket(self, chatMid, ticket):
        req = AcceptChatInvitationByTicketRequest()
        req.reqSeq = 0
        req.chatMid = chatMid
        req.ticketId = ticket
        return self.talk.acceptChatInvitationByTicket(req)

    @loggedIn
    def acceptChatInvitation(self, chatMid):
        req = AcceptChatInvitationRequest()
        req.reqSeq = 0
        req.chatMid = chatMid
        return self.talk.acceptChatInvitation(req)

    @loggedIn
    def cancelChatInvitation(self, chatMid, targets={}):
        req = CancelChatInvitationRequest()
        req.reqSeq = 0
        req.chatMid = chatMid
        req.targetUserMids = targets
        return self.talk.cancelChatInvitation(req)

    @loggedIn
    def createChat(self,name,targets,picturePath=None):
        req = CreateChatRequest()
        req.reqSeq = 0
        req.type = 0
        req.name = name
        req.targetUserMids = targets
        req.picturePath = picturePath
        return self.talk.createChat(req)

    @loggedIn
    def deleteOtherFromChat(self,chatMid,targets={}):
        req = DeleteOtherFromChatRequest()
        req.reqSeq = 0
        req.chatMid = chatMid
        req.targetUserMids = targets
        return self.talk.deleteOtherFromChat(req)

    @loggedIn
    def deleteSelfFromChat(self,chatMid):
        req = DeleteSelfFromChatRequest()
        req.reqSeq = 0
        req.chatMid = chatMid
        return self.talk.deleteSelfFromChat(req)

    @loggedIn
    def findChatByTicket(self,ticket):
        req = FindChatByTicketRequest()
        req.ticketId = ticket
        return self.talk.findChatByTicket(req)

    @loggedIn
    def getAllChatMids(self):
        req = GetAllChatMidsRequest()
        req.withMembersChats = True
        req.withInvitedChats = True
        return self.talk.getAllChatMids(req,1)

    @loggedIn
    def inviteIntoChat(self,chatMid,targets={}):
        req = InviteIntoChatRequest()
        req.reqSeq = 0
        req.chatMid = chatMid
        req.targetUserMids = targets
        return self.talk.inviteIntoChat(req)

    @loggedIn
    def reissueChatTicket(self,chatMid):
        req = ReissueChatTicketRequest()
        req.reqSeq = 0
        req.chatMid = chatMid
        return self.talk.reissueChatTicket(req)

    @loggedIn
    def getChats(self,chatMids=[]):
        req = GetChatsRequest()
        req.chatMids = chatMids
        req.withMembers = True
        req.withInvitees = True
        return self.talk.getChats(req)

    @loggedIn
    def rejectChatInvitation(self,chatMid):
        req = RejectChatInvitationRequest()
        req.reqSeq = 0
        req.chatMid = chatMids
        return self.talk.rejectChatInvitation(req)

    @loggedIn
    def updateChat(self,chat,updatedAttribute):
        """
            1: Chat chatMid,
            2: int updatedAttribute (
                1: name, 
                2: picture_status, 
                4: PREVENTED_JOIN_BY_TICKET, 
                8: NOTIFICATION_SETTING, 
                32: FAVORITE_TIMESTAMP, 
                64: CHAT_TYPE
            )
        """
        req = UpdateChatRequest()
        req.reqSeq = 0
        req.chat = chat
        req.updatedAttribute = updatedAttribute
        return self.talk.updateChat(req)


    @loggedIn
    def generateFooterTemplate(self,title=None,link=None,iconlink=None,isHelper=False):
        if isHelper:
            title = title
            link = "https://line.me/R/ti/p/~kyu.za"
            iconlink = iconlink
        userTicket = self.generateUserTicket()
        title = title if title else "Kyuza"
        link = link if link else 'https://line.me/R/ti/p/'+userTicket
        iconlink = iconlink if iconlink else 'https://obs.line-apps.com/os/p/%s' % self.profile.mid
        data = {"label":title,"iconUrl":iconlink,"linkUrl":link}
        return data

    @loggedIn
    def Notif(self, op):
        ret = 'Operation : ( %i ) %s' % (op.type, OpType._VALUES_TO_NAMES[op.type].replace('_', ' '))
        group = self.getCompactGroup(op.param1)
        executor = self.getContact(op.param2).displayName
        timeEx = datetime.now(tz=self.time)
        if op.type == 11 or op.type == 122:
            if op.param3 == '1':
                ret += '\n %s Was update group name : %s' % (executor, group.name)
            if op.param3 == '2':
                ret += '\n %s Was update group picture : %s' % (executor, group.name)
            if op.param3 == '4':
                if group.preventedJoinByTicket == False:
                    ret += '\n %s Was allowed group invitation by Ticket in Group : %s\n Link : https://line.me/R/ti/g/%s' % (executor, group.name, self.reissueGroupTicket(op.param1))
                else:
                    ret += '\n %s Was blocked group invitation by Ticket in Group : %s' % (executor, group.name)
        else:
            victim = self.getContact(op.param3).displayName
            if op.type == 13 or op.type == 124:
                ret += '\n %s Was invite me into Group : %s' % (executor, group.name)
            if op.type == 19 or op.type == 133:
                if self.getProfile().mid not in op.param3:
                    ret += '\n Victim : %s\n Executor : %s\n Group : %s' % (victim, executor, group.name)
                if self.getProfile().mid in op.param3:
                    ret += '\n %s Was kickout me From Group : %s' % (executor, group.name)
        ret += '\nTime Executed :\n Date: '+ datetime.strftime(timeEx,'%Y-%m-%d')+"\n Time :  "+ datetime.strftime(timeEx,'%H:%M:%S')
        return ret

    @loggedIn
    def updateProfile(self, profileObject):
        return self.talk.updateProfile(0, profileObject)

    @loggedIn
    def updateSettings(self, settingObject):
        return self.talk.updateSettings(0, settingObject)

    @loggedIn
    def updateProfileAttribute(self, attrId, value):
        return self.talk.updateProfileAttribute(0, attrId, value)

    @loggedIn
    def updateContactSetting(self, mid, flag, value):
        return self.talk.updateContactSetting(0, mid, flag, value)

    @loggedIn
    def deleteContact(self, mid):
        return self.updateContactSetting(mid, 16, 'True')

    @loggedIn
    def renameContact(self, mid, name):
        return self.updateContactSetting(mid, 2, name)

    @loggedIn
    def addToFavoriteContactMids(self, mid):
        return self.updateContactSetting(mid, 8, 'True')

    @loggedIn
    def addToHiddenContactMids(self, mid):
        return self.updateContactSetting(mid, 4, 'True')

    """Operation"""

    @loggedIn
    def fetchOps(self):
        return self.poll.fetchOps()

    """Message"""

    @loggedIn
    def sendMessage(self, to, text, contentMetadata={}, contentType=0):
        msg = Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = text
        msg.contentType, msg.contentMetadata = contentType, contentMetadata
        return self.talk.sendMessage(0, msg)

    @loggedIn
    def sendMessageObject(self, msg):
        to = msg.to
        return self.talk.sendMessage(0, msg)

    @loggedIn
    def sendLocation(self, to, address, latitude, longitude, phone=None, contentMetadata={}):
        msg = Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = "Location by Hello World"
        msg.contentType, msg.contentMetadata = 0, contentMetadata
        location = Location()
        location.address = address
        location.phone = phone
        location.latitude = float(latitude)
        location.longitude = float(longitude)
        location.title = "Location"
        msg.location = location
        return self.talk.sendMessage(0, msg)

    @loggedIn
    def sendMessageMusic(self, to, title=None, subText=None, url=None, iconurl=None, contentMetadata={}):
        """
        a : Android
        i : Ios
        """
        self.profile = self.getProfile()
        self.userTicket = self.generateUserTicket()
        title = title if title else 'LINE MUSIC'
        subText = subText if subText else self.profile.displayName
        url = url if url else 'https://line.me/R/ti/p/' + self.userTicket
        iconurl = iconurl if iconurl else 'https://obs.line-apps.com/os/p/%s' % self.profile.mid
        msg = Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = title
        msg.contentType = 19
        msg.contentMetadata = {
            'text': title,
            'subText': subText,
            'a-installUrl': url,
            'i-installUrl': url,
            'a-linkUri': url,
            'i-linkUri': url,
            'linkUri': url,
            'previewUrl': iconurl,
            'type': 'mt',
            'a-packageName': 'com.spotify.music',
            'countryCode': 'JP',
            'id': 'mt000000000a6b79f9'
        }
        if contentMetadata:
            msg.contentMetadata.update(contentMetadata)
        return self.talk.sendMessage(0, msg)

    @loggedIn
    def generateMessageFooter(self, title=None, link=None, iconlink=None):
        self.profile = self.getProfile()
        self.userTicket = self.generateUserTicket()
        title = title if title else self.profile.displayName
        link = link if link else 'https://line.me/R/ti/p/' + self.userTicket
        iconlink = iconlink if iconlink else 'https://obs.line-apps.com/os/p/%s' % self.profile.mid
        return {'AGENT_NAME': title, 'AGENT_LINK': link, 'AGENT_ICON': iconlink}

    @loggedIn
    def sendMessageWithFooter(self, to, text, title=None, link=None, iconlink=None, contentMetadata={}):
        msg = Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = text
        msg.contentType = 0
        msg.contentMetadata = self.generateMessageFooter(title, link, iconlink)
        if contentMetadata:
            msg.contentMetadata.update(contentMetadata)
        return self.talk.sendMessage(0, msg)

    @loggedIn
    def generateReplyMessage(self, relatedMessageId):
        msg = Message()
        msg.relatedMessageServiceCode = 1
        msg.messageRelationType = 3
        msg.relatedMessageId = str(relatedMessageId)
        return msg

    @loggedIn
    def sendReplyMessage(self, relatedMessageId, to, text, contentMetadata={}, contentType=0):
        msg = self.generateReplyMessage(relatedMessageId)
        msg.to = to
        msg.text = text
        msg.contentType = contentType
        msg.contentMetadata = contentMetadata
        return self.talk.sendMessage(0, msg)

    @loggedIn
    def sendMention(self, to, mid, firstmessage='', lastmessage=''):
        arrData = ""
        text = "%s " %(str(firstmessage))
        arr = []
        mention = "@zeroxyuuki "
        slen = str(len(text))
        elen = str(len(text) + len(mention) - 1)
        arrData = {'S':slen, 'E':elen, 'M':mid}
        arr.append(arrData)
        text += mention + str(lastmessage)
        self.sendMessage(to, text, {'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)

    @loggedIn
    def sendMentionV2(self, to, text="", mids=[], isUnicode=False):
        arrData = ""
        arr = []
        mention = "@kyuza "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ""
            unicode = ""
            if isUnicode:
                for mid in mids:
                    unicode += str(texts[mids.index(mid)].encode('unicode-escape'))
                    textx += str(texts[mids.index(mid)])
                    slen = len(textx) if unicode == textx else len(textx) + unicode.count('U0')
                    elen = len(textx) + 10
                    arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                    arr.append(arrData)
                    textx += mention
            else:
                for mid in mids:
                    textx += str(texts[mids.index(mid)])
                    slen = len(textx)
                    elen = len(textx) + 10
                    arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                    arr.append(arrData)
                    textx += mention
            textx += str(texts[len(mids)])
        else:
            raise Exception("Invalid mention position")
        self.sendMessage(to, textx, {'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)
        
    @loggedIn
    def sendMentionV3(self, msg_id,to, text="", mids=[], isUnicode=False):
        arrData = ""
        arr = []
        mention = "@kyuza "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ""
            unicode = ""
            if isUnicode:
                for mid in mids:
                    unicode += str(texts[mids.index(mid)].encode('unicode-escape'))
                    textx += str(texts[mids.index(mid)])
                    slen = len(textx) if unicode == textx else len(textx) + unicode.count('U0')
                    elen = len(textx) + 10
                    arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                    arr.append(arrData)
                    textx += mention
            else:
                for mid in mids:
                    textx += str(texts[mids.index(mid)])
                    slen = len(textx)
                    elen = len(textx) + 10
                    arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                    arr.append(arrData)
                    textx += mention
            textx += str(texts[len(mids)])
        else:
            raise Exception("Invalid mention position")
        self.sendReplyMessage(msg_id,to, textx, {'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)

    """ Usage:
        @to Integer
        @text String
        @dataMid List of user Mid
    """
    @loggedIn
    def sendMessageWithMention(self, to, text='', dataMid=[]):
        arr = []
        list_text=''
        if '[list]' in text.lower():
            i=0
            for l in dataMid:
                list_text+='\n@[list-'+str(i)+']'
                i=i+1
            text=text.replace('[list]', list_text)
        elif '[list-' in text.lower():
            text=text
        else:
            i=0
            for l in dataMid:
                list_text+=' @[list-'+str(i)+']'
                i=i+1
            text=text+list_text
        i=0
        for l in dataMid:
            mid=l
            name='@[list-'+str(i)+']'
            ln_text=text.replace('\n',' ')
            if ln_text.find(name):
                line_s=int(ln_text.index(name))
                line_e=(int(line_s)+int(len(name)))
            arrData={'S': str(line_s), 'E': str(line_e), 'M': mid}
            arr.append(arrData)
            i=i+1
        contentMetadata={'MENTION':str('{"MENTIONEES":' + json.dumps(arr).replace(' ','') + '}')}
        return self.sendMessage(to, text, contentMetadata)

    @loggedIn
    def sendSticker(self, to, stickerVer, packageId, stickerId):
        contentMetadata = {
            'STKVER': stickerVer,
            'STKPKGID': packageId,
            'STKID': stickerId
        }
        return self.sendMessage(to, '', contentMetadata, 7)

    
    @loggedIn
    def sendStickerWithReply(self, msg, stickerVer, packageId, stickerId):
        contentMetadata = {
            'STKVER': stickerVer,
            'STKPKGID': packageId,
            'STKID': stickerId
        }
        return self.sendReplyMessage(msg.id,msg.to, '', contentMetadata, 7)
        
    @loggedIn
    def sendContact(self, to, mid):
        contentMetadata = {'mid': mid}
        return self.sendMessage(to, '', contentMetadata, 13)

    @loggedIn
    def sendGift(self, to, productId, productType):
        if productType not in ['theme','sticker']:
            raise Exception('Invalid productType value')
        contentMetadata = {
            'MSGTPL': str(randint(0, 12)),
            'PRDTYPE': productType.upper(),
            'STKPKGID' if productType == 'sticker' else 'PRDID': productId
        }
        return self.sendMessage(to, '', contentMetadata, 9)

    @loggedIn
    def giftMessage(self,to):
        a = ("5","7","6","8")
        b = random.choice(a)
        return self.sendMessage(to, text=None, contentMetadata={'PRDTYPE': 'STICKER','STKVER': '1','MSGTPL': b,'STKPKGID': '1380280'}, contentType=9)

    @loggedIn
    def sendMessageAwaitCommit(self, to, text, contentMetadata={}, contentType=0):
        msg = Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = text
        msg.contentType, msg.contentMetadata = contentType, contentMetadata
        return self.talk.sendMessageAwaitCommit(0, msg)

    @loggedIn
    def unsendMessage(self, messageId):
        return self.talk.unsendMessage(0, messageId)

    @loggedIn
    def requestResendMessage(self, senderMid, messageId):
        return self.talk.requestResendMessage(0, senderMid, messageId)

    @loggedIn
    def respondResendMessage(self, receiverMid, originalMessageId, resendMessage, errorCode):
        return self.talk.respondResendMessage(0, receiverMid, originalMessageId, resendMessage, errorCode)

    @loggedIn
    def removeMessage(self, messageId):
        return self.talk.removeMessage(messageId)
    
    @loggedIn
    def sendMessageToMyHome(self, messageId):
        return self.talk.sendMessageToMyHome(0, messageId)
    
    @loggedIn
    def removeAllMessages(self, lastMessageId):
        return self.talk.removeAllMessages(0, lastMessageId)

    @loggedIn
    def removeMessageFromMyHome(self, messageId):
        return self.talk.removeMessageFromMyHome(messageId)

    @loggedIn
    def destroyMessage(self, chatId, messageId):
        return self.talk.destroyMessage(0, chatId, messageId, sessionId)
    
    @loggedIn
    def sendChatChecked(self, consumer, messageId):
        return self.talk.sendChatChecked(0, consumer, messageId)

    @loggedIn
    def sendEvent(self, messageObject):
        return self.talk.sendEvent(0, messageObject)

    @loggedIn
    def getLastReadMessageIds(self, chatId):
        return self.talk.getLastReadMessageIds(0, chatId)

    @loggedIn
    def getRecentMessagesV2(self, chatId, count=1001):
        return self.talk.getRecentMessagesV2(chatId,count)

    @loggedIn
    def getPreviousMessagesV2WithReadCount(self, messageBoxId, endMessageId, messagesCount=50):
        return self.talk.getPreviousMessagesV2WithReadCount(messageBoxId, endMessageId, messagesCount)

    """Object"""

    @loggedIn
    def sendImage(self, to, path,delete=False):
        objectId = self.sendMessage(to=to, text=None, contentType = 1).id
        self.uploadObjTalk(path=path, type='image', returnAs='bool', objId=objectId)
        if delete:self.deleteFile(path)

    @loggedIn
    def sendImageBarengan(self,to,path,delete=False):
        objectId = self.sendMessage(to=to, text=None, contentType = 1).id
        objectId2 = self.sendMessage(to=to, text=None, contentType = 1, contentMetadata={"OBS_POP":"kr-1","GID":"{}".format(int(objectId)+1)}).id
        self.uploadObjTalk(path=path, type='image', returnAs='bool', objId=objectId)
        self.uploadObjTalk(path=path, type='image', returnAs='bool', objId=objectId2)

    @loggedIn
    def sendImageWithReply(self, msg, path,delete=False):
        objectId = self.sendReplyMessage(msg.id, to=msg.to, text=None, contentType = 1).id
        self.uploadObjTalk(path=path, type='image', returnAs='bool', objId=objectId)
        if delete:self.deleteFile(path)

    @loggedIn
    def sendImageWithURL(self, to, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendImage(to, path)
    
    @loggedIn
    def sendImageWithURLV2(self, msg, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendImageWithReply(msg, path)

    @loggedIn
    def sendGIF(self, to, path,delete=False):
        self.uploadObjTalk(path=path, type='gif', returnAs='bool', to=to)
        if delete:self.deleteFile(path)

    @loggedIn
    def sendGIFWithURL(self, to, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendGIF(to, path)

    @loggedIn
    def sendVideo(self, to, path,delete=False):
        objectId = self.sendMessage(to=to, text=None, contentMetadata={'VIDLEN': '60000','DURATION': '60000'}, contentType = 2).id
        self.uploadObjTalk(path=path, type='video',returnAs='bool', objId=objectId)
        if delete:self.deleteFile(path)

    @loggedIn
    def sendVideoWithURL(self, to, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendVideo(to, path)

    @loggedIn
    def sendAudio(self, to, path,delete=False):
        objectId = self.sendMessage(to=to, text=None, contentType = 3).id
        self.uploadObjTalk(path=path, type='audio', returnAs='bool', objId=objectId)
        if delete:self.deleteFile(path)

    @loggedIn
    def sendAudioWithURL(self, to, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendAudio(to, path)

    @loggedIn
    def sendFile(self, to, path, file_name='',ct = ''):
        file_size = len(open(path, 'rb').read())
        if file_name == '':
            file_name = ntpath.basename(path)
        if ct == '':
            ct = {'FILE_NAME': str(file_name),'FILE_SIZE': str(file_size)}
        objectId = self.sendMessage(to=to, text=None, contentMetadata=ct, contentType = 14).id
        return self.uploadObjTalk(path=path, type='file', returnAs='bool', objId=objectId)

    @loggedIn
    def sendFileWithURL(self, to, url, fileName=''):
        path = self.downloadFileURL(url, 'path')
        return self.sendFile(to, path, fileName)

    """Contact"""
        
    @loggedIn
    def blockContact(self, mid):
        return self.talk.blockContact(0, mid)

    @loggedIn
    def unblockContact(self, mid):
        return self.talk.unblockContact(0, mid)

    @loggedIn
    def findAndAddContactByMetaTag(self, userid, reference):
        return self.talk.findAndAddContactByMetaTag(0, userid, reference)

    @loggedIn
    def findAndAddContactsByMid(self, mid):
        return self.talk.findAndAddContactsByMid(0, mid, 0, '')

    @loggedIn
    def findAndAddContactsByEmail(self, emails=[]):
        return self.talk.findAndAddContactsByEmail(0, emails)

    @loggedIn
    def findAndAddContactsByUserid(self, userid):
        return self.talk.findAndAddContactsByUserid(0, userid)

    @loggedIn
    def findContactsByUserid(self, userid):
        return self.talk.findContactByUserid(userid)

    @loggedIn
    def findContactByTicket(self, ticketId):
        return self.talk.findContactByUserTicket(ticketId)

    @loggedIn
    def getAllContactIds(self):
        return self.talk.getAllContactIds()

    @loggedIn
    def getBlockedContactIds(self):
        return self.talk.getBlockedContactIds()

    @loggedIn
    def getContact(self, mid):
        return self.talk.getContact(mid)

    @loggedIn
    def getContacts(self, midlist):
        return self.talk.getContacts(midlist)

    @loggedIn
    def getFavoriteMids(self):
        return self.talk.getFavoriteMids()

    @loggedIn
    def getHiddenContactMids(self):
        return self.talk.getHiddenContactMids()

    @loggedIn
    def tryFriendRequest(self, midOrEMid, friendRequestParams, method=1):
        return self.talk.tryFriendRequest(midOrEMid, method, friendRequestParams)

    @loggedIn
    def makeUserAddMyselfAsContact(self, contactOwnerMid):
        return self.talk.makeUserAddMyselfAsContact(contactOwnerMid)

    @loggedIn
    def getContactWithFriendRequestStatus(self, id):
        return self.talk.getContactWithFriendRequestStatus(id)

    @loggedIn
    def reissueUserTicket(self, expirationTime=100, maxUseCount=100):
        return self.talk.reissueUserTicket(expirationTime, maxUseCount)
    
    @loggedIn
    def cloneContactProfile(self, mid, channel):
        contact = self.getContact(mid)
        path = "http://dl.profile.line-cdn.net/" + contact.pictureStatus
        path = self.downloadFileURL(path)
        self.updateProfilePicture(path)
        profile = self.profile
        profile.displayName = contact.displayName
        profile.statusMessage = contact.statusMessage
        if channel.getProfileCoverId(mid) is not None:
            channel.updateProfileCoverById(channel.getProfileCoverId(mid))
        return self.updateProfile(profile)

    """Group"""

    @loggedIn
    def getChatRoomAnnouncementsBulk(self, chatRoomMids):
        return self.talk.getChatRoomAnnouncementsBulk(chatRoomMids)

    @loggedIn
    def getChatRoomAnnouncements(self, chatRoomMid):
        return self.talk.getChatRoomAnnouncements(chatRoomMid)

    @loggedIn
    def createChatRoomAnnouncement(self, chatRoomMid, type, contents):
        return self.talk.createChatRoomAnnouncement(0, chatRoomMid, type, contents)

    @loggedIn
    def removeChatRoomAnnouncement(self, chatRoomMid, announcementSeq):
        return self.talk.removeChatRoomAnnouncement(0, chatRoomMid, announcementSeq)

    @loggedIn
    def getGroupWithoutMembers(self, groupId):
        return self.talk.getGroupWithoutMembers(groupId)
    
    @loggedIn
    def findGroupByTicket(self, ticketId):
        return self.talk.findGroupByTicket(ticketId)

    @loggedIn
    def findGroupByTicketV2(self, ticketId):
        return self.talk.findGroupByTicketV2(ticketId)

    @loggedIn
    def acceptGroupInvitation(self, groupId):
        return self.talk.acceptGroupInvitation(0, groupId)

    @loggedIn
    def acceptGroupInvitationByTicket(self, groupId, ticketId):
        return self.talk.acceptGroupInvitationByTicket(0, groupId, ticketId)

    @loggedIn
    def acceptGroupInvitationByTicketV2(self, ticketId):
        group = self.findGroupByTicket(ticketId)
        return self.talk.acceptGroupInvitationByTicket(0, group.id, ticketId)

    @loggedIn
    def cancelGroupInvitation(self, groupId, contactIds):
        return self.talk.cancelGroupInvitation(0, groupId, contactIds)

    @loggedIn
    def createGroup(self, name, midlist):
        return self.talk.createGroup(0, name, midlist)

    @loggedIn
    def getGroup(self, groupId):
        return self.talk.getGroup(groupId)

    @loggedIn
    def getGroups(self, groupIds):
        return self.talk.getGroups(groupIds)

    @loggedIn
    def getGroupsV2(self, groupIds):
        return self.talk.getGroupsV2(groupIds)

    @loggedIn
    def getCompactGroup(self, groupId):
        return self.talk.getCompactGroup(groupId)

    @loggedIn
    def getCompactRoom(self, roomId):
        return self.talk.getCompactRoom(roomId)

    @loggedIn
    def getGroupIdsByName(self, groupName):
        gIds = []
        for gId in self.getGroupIdsJoined():
            g = self.getCompactGroup(gId)
            if groupName in g.name:
                gIds.append(gId)
        return gIds

    @loggedIn
    def getGroupIdsInvited(self):
        return self.talk.getGroupIdsInvited()

    @loggedIn
    def getGroupIdsJoined(self):
        return self.talk.getGroupIdsJoined()

    @loggedIn
    def updateGroupPreferenceAttribute(self, groupMid, updatedAttrs):
        return self.talk.updateGroupPreferenceAttribute(0, groupMid, updatedAttrs)

    @loggedIn
    def inviteIntoGroup(self, groupId, midlist):
        try:
            for mid in midList:
                self.findAndAddContactsByMid(mid)
        except:pass
        return self.talk.inviteIntoGroup(0, groupId, midlist)

    @loggedIn
    def kickoutFromGroup(self, groupId, midlist):
        return self.talk.kickoutFromGroup(0, groupId, midlist)

    @loggedIn
    def leaveGroup(self, groupId):
        return self.talk.leaveGroup(0, groupId)

    @loggedIn
    def rejectGroupInvitation(self, groupId):
        return self.talk.rejectGroupInvitation(0, groupId)

    @loggedIn
    def reissueGroupTicket(self, groupId):
        return self.talk.reissueGroupTicket(groupId)

    @loggedIn
    def updateGroup(self, groupObject):
        return self.talk.updateGroup(0, groupObject)

    """Room"""

    @loggedIn
    def createRoom(self, midlist):
        return self.talk.createRoom(0, midlist)

    @loggedIn
    def getRoom(self, roomId):
        return self.talk.getRoom(roomId)

    @loggedIn
    def inviteIntoRoom(self, roomId, midlist):
        return self.talk.inviteIntoRoom(0, roomId, midlist)

    @loggedIn
    def leaveRoom(self, roomId):
        return self.talk.leaveRoom(0, roomId)

    """Call"""
        
    @loggedIn
    def acquireCallTalkRoute(self, to):
        return self.talk.acquireCallRoute(to)

    @loggedIn
    def requestsWeb(self,url):
        r = requests.get("{}".format(url))
        data = r.text
        data = json.loads(data)
        return data
    
    """Report"""

    @loggedIn
    def reportSpam(self, chatMid, memberMids=[], spammerReasons=[], senderMids=[], spamMessageIds=[], spamMessages=[]):
        return self.talk.reportSpam(chatMid, memberMids, spammerReasons, senderMids, spamMessageIds, spamMessages)
        
    @loggedIn
    def reportContacts(self,contactReports=[]):
        return self.talk.reportContacts(self.getLastOpRevision(),3,contactReports,1)

    @loggedIn
    def reportSpammer(self, spammerMid, spammerReasons=[], spamMessageIds=[]):
        return self.talk.reportSpammer(spammerMid, spammerReasons, spamMessageIds)
