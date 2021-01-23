# -*- coding: utf-8 -*-
from .client import LINE
from types import *

import os, sys, threading, time

class OEPoll(object):
    OpInterrupt = {}
    client = None
    __squareSubId = {}
    __squareSyncToken = {}

    def __init__(self, client):
        if type(client) is not LINE:
            raise Exception('You need to set LINE instance to initialize OEPoll')
        self.client = client
        self.localRev = -1
        self.globalRev = 0
        self.individualRev = 0
    
    def __execute(self, op, threading):
        try:
            if threading:
                _td = threading.Thread(target=self.OpInterrupt[op.type](op))
                _td.daemon = False
                _td.start()
            else:
                self.OpInterrupt[op.type](op)
        except Exception as e:
            self.client.log(e)

    def addOpInterruptWithDict(self, OpInterruptDict):
        self.OpInterrupt.update(OpInterruptDict)

    def addOpInterrupt(self, OperationType, DisposeFunc):
        self.OpInterrupt[OperationType] = DisposeFunc
    
    def fetchOps(self):
        return self.client.poll.fetchOps(self.localRev,15,self.globalRev,self.individualRev)

    # def singleFetchSquareChat(self, squareChatMid, limit=1):
    #     if squareChatMid not in self.__squareSubId:
    #         self.__squareSubId[squareChatMid] = 0
    #     if squareChatMid not in self.__squareSyncToken:
    #         self.__squareSyncToken[squareChatMid] = ''
        
    #     sqcEvents = self.client.fetchSquareChatEvents(squareChatMid, subscriptionId=self.__squareSubId[squareChatMid], syncToken=self.__squareSyncToken[squareChatMid], limit=limit, direction=1)
    #     self.__squareSubId[squareChatMid] = sqcEvents.subscription
    #     self.__squareSyncToken[squareChatMid] = sqcEvents.syncToken

    #     return sqcEvents.events