# -*- coding: utf-8 -*-
from typing import List, Dict, Optional
from lib.thrift.transport.THttpClient import THttpClient
from lib.thrift.protocol.TCompactProtocol import TCompactProtocol
from lib.akad import AuthService, TalkService
from lib.akad.ttypes import LoginRequest, CreateQrSessionRequest, CreateQrCodeRequest, CheckQrCodeVerifiedRequest, VerifyCertificateRequest, QrCodeLoginRequest, CreatePinCodeRequest, SecondaryQrCodeException, CheckPinCodeVerifiedRequest, QrCodeLoginResponse
from lib.akad import SecondaryQrCodeLoginPermitNoticeService, SecondaryQrCodeLoginService
from .callback import Callback

import json, requests, time, os
import axolotl_curve25519 as curve
import urllib.parse
import base64

class LineConfig(object):
    LINE_HOST_DOMAIN 			= 'https://legy-jp-addr.line.naver.jp'
    LINE_LOGIN_QUERY_PATH 		= '/api/v4p/rs'
    LINE_AUTH_QUERY_PATH 		= '/api/v4/TalkService.do'
    LINE_API_QUERY_PATH_FIR 	= '/S4'
    LINE_CERTIFICATE_PATH 		= '/Q'
    LINE_SECONDARY_LOGIN_REQUEST_V1 = '/acct/lgn/sq/v1'
    LINE_SECONDARY_LOGIN_CHECK_V1 = '/acct/lp/lgn/sq/v1'

    APP_VERSION = {
        'ANDROID': '10.8.3',
        'IOS': '10.8.0',
        'ANDROIDLITE': '2.14.0',
        'DESKTOPWIN': '6.0.3',
        'DESKTOPMAC': '6.0.3',
        'IOSIPAD': '10.8.0',
        'CHROMEOS': '2.3.8',
        'DEFAULT': '10.6.5'
    }

    SYSTEM_VERSION = {
        'ANDROID': '10.0',
        'IOS': '13.4.1',
        'ANDROIDLITE': '10.0',
        'DESKTOPWIN': '10.0',
        'DESKTOPMAC': '10.15.1',
        'IOSIPAD': '13.4.1',
        'CHROMEOS': '81.0',
        'DEFAULT': '10.0'
    }

    APP_TYPE    = 'IOSIPAD'
    APP_VER     = APP_VERSION[APP_TYPE] if APP_TYPE in APP_VERSION else APP_VERSION['DEFAULT']
    CARRIER     = '51089, 1-0'
    SYSTEM_NAME = 'K-System'
    SYSTEM_VER  = SYSTEM_VERSION[APP_TYPE] if APP_TYPE in SYSTEM_VERSION else SYSTEM_VERSION['DEFAULT']
    IP_ADDR     = '8.8.8.8'

    def __init__(self, appName=None):
        if appName:
            self.APP_TYPE = appName
            self.APP_VER = self.APP_VERSION[self.APP_TYPE] if self.APP_TYPE in self.APP_VERSION else self.APP_VERSION['DEFAULT']
        self.APP_NAME = '{}\t{}\t{}\t{}'.format(self.APP_TYPE, self.APP_VER, self.SYSTEM_NAME, self.SYSTEM_VER)
        self.USER_AGENT = 'Line/%s' % self.APP_VER
		
class LineAuth(object):
    authToken 	= ""
    certificate = None

    def __init__(self, appName=None, systemName=None):
        self.config = LineConfig()
        self.session = requests.session()
        self.callback = Callback(self.__defaultCallback)
        if appName is None:
            appName = self.config.APP_NAME
        if systemName is None:
            systemName = self.config.SYSTEM_NAME
        self.appName = LineConfig(appName).APP_NAME
        self.systemName = systemName
        self.userAgent = self.config.USER_AGENT

        self.headers = {
            'User-Agent': self.userAgent,
            'X-Line-Application': self.appName+";SECONDARY",
            'x-lal': 'en_US',
        }

    def createTransport(self, url, update_headers=None, service=None):
        if(update_headers is not None):
            self.headers.update(update_headers)
        transport 	= THttpClient(url)
        transport.setCustomHeaders(self.headers)
        protocol 	= TCompactProtocol.TCompactProtocol(transport)
        client 		= service(protocol)
        return client

    def getJson(self, url, headers=None):
        if headers is None:
            return json.loads(self.session.get(url).text)
        else:
            return json.loads(self.session.get(url, headers=headers).text)

    def generateQrCode(self,certificate: Optional[str] = None):
        if certificate:
            self.certificate = certificate
        session_id = self.create_qrcode_session()
        url = self.create_qrcode(session_id)
        secret = self.create_secret()
        result = f"{url}{secret}"
        self.callback.QrUrl(result,False)
        pincode = self.check_qrcode_and_verify_certificate(session_id,self.certificate)
        if pincode:
            self.callback.PinVerified(pincode)
            self.check_pincode(session_id)
        result = self.login_with_qrcode_request(session_id, self.systemName)
        print(result)

    def generatePinCode(self,certificate: Optional[str] = None):
        pincode = self.check_qrcode_and_verify_certificate(self.session_id,certificate)
        if pincode:
            return pincode
        return None


    def generateAuthToken(self):
        self.check_pincode(self.session_id)
        result = self.login_with_qrcode_request(self.session_id, self.systemName)
        self.authToken = result.accessToken
        self.certificate = result.certificate
        return result

    def create_qrcode_session(self) -> str:
        self.lr = self.create_secondary_qr_code_login_service_client()
        return self.lr.createSession(CreateQrSessionRequest()).authSessionId

    def create_qrcode(self, session_id: str) -> str:
        return self.lr.createQrCode(CreateQrCodeRequest(session_id)).callbackUrl

    def check_qrcode_and_verify_certificate(self, session_id: str, certificate: Optional[str]) -> Optional[str]:
        self.headers.update({"X-Line-Access":""})
        self.lc = self.create_secondary_qr_code_login_permit_notice_service_client()
        self.lc.checkQrCodeVerified(CheckQrCodeVerifiedRequest(session_id))
        print(type(certificate))
        try:
            self.lr.verifyCertificate(VerifyCertificateRequest(session_id, certificate))
            return None
        except SecondaryQrCodeException:
            return self.lr.createPinCode(CreatePinCodeRequest(session_id)).pinCode

    def check_pincode(self, session_id: str):
        self.lc.checkPinCodeVerified(CheckPinCodeVerifiedRequest(session_id))

    def login_with_qrcode_request(self, session_id: str, system_name: str) -> QrCodeLoginResponse:
        return self.lr.qrCodeLogin(QrCodeLoginRequest(session_id, system_name, autoLoginIsRequired=True))

    def create_secret(self):
        private_key = curve.generatePrivateKey(os.urandom(32))
        public_key = curve.generatePublicKey(private_key)

        secret = urllib.parse.quote(base64.b64encode(public_key).decode())
        version = 1
        return f"?secret={secret}&e2eeVersion={version}"

    def create_secondary_qr_code_login_service_client(self) -> SecondaryQrCodeLoginService.Client:
        return self.createTransport(self.config.LINE_HOST_DOMAIN + self.config.LINE_SECONDARY_LOGIN_REQUEST_V1, None, SecondaryQrCodeLoginService.Client)

    def create_secondary_qr_code_login_permit_notice_service_client(self) -> SecondaryQrCodeLoginPermitNoticeService.Client:
        return self.createTransport(self.config.LINE_HOST_DOMAIN + self.config.LINE_SECONDARY_LOGIN_CHECK_V1, None, SecondaryQrCodeLoginPermitNoticeService.Client)

    def __defaultCallback(self, str):
        print(str)