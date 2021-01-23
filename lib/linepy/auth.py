# -*- coding: utf-8 -*-
from lib.akad.ttypes import IdentityProvider, LoginResultType, LoginRequest, LoginType
#from lib.akad.ttypes import CreateQrSessionRequest, CreateQrCodeRequest, CheckQrCodeVerifiedRequest, VerifyCertificateRequest, QrCodeLoginRequest, CreatePinCodeRequest, SecondaryQrCodeException, CheckPinCodeVerifiedRequest, QrCodeLoginResponse
from .server import Server
from .session import Session
from typing import List, Dict, Optional
from .callback import Callback
# from geventhttpclient import HTTPClient
# from geventhttpclient.url import URL
# from thrift.protocol.TCompactProtocol import TCompactProtocolAccelerated
# from lib.akad import SecondaryQrCodeLoginPermitNoticeService, SecondaryQrCodeLoginService
from .e2ee import E2EE
import rsa, os
import urllib.parse
import base64

class Auth(object):
    isLogin     = False
    authToken   = ""

    def __init__(self):
        self.server = Server(self.appType)
        self.callback = Callback(self.__defaultCallback)
        self.server.setHeadersWithDict({
            'User-Agent': self.server.USER_AGENT,
            'X-Line-Application': self.server.APP_NAME,
            'X-Line-Carrier': self.server.CARRIER,
            'x-lal': 'en_US'
        })
        # url = URL(self.server.LINE_HOST_DOMAIN)
        # self.__client = HTTPClient(url.host, url.port, concurrency=30, ssl=True, connection_timeout=180.0, network_timeout=180.0)

    def __loadSession(self):
        self.talk       = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_API_QUERY_PATH_FIR, self.customThrift).Talk()
        self.nuke       = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_API_QUERY_PATH_FIR, self.customThrift).Nuke()
        self.poll       = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_POLL_QUERY_PATH_FIR, self.customThrift).Talk()
        self.channel    = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_CHAN_QUERY_PATH, self.customThrift).Channel()
        self.liff       = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_LIFF_QUERY_PATH, self.customThrift).Liff()
        self.shop       = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_SHOP_QUERY_PATH, self.customThrift).Shop()

        self.isLogin = True

    def __loginRequest(self, type, data):
        lReq = LoginRequest()
        if type == '0':
            lReq.type = LoginType.ID_CREDENTIAL
            lReq.identityProvider = data['identityProvider']
            lReq.identifier = data['identifier']
            lReq.password = data['password']
            lReq.keepLoggedIn = data['keepLoggedIn']
            lReq.accessLocation = data['accessLocation']
            lReq.systemName = data['systemName']
            lReq.certificate = data['certificate']
            lReq.e2eeVersion = data['e2eeVersion']
        elif type == '1':
            lReq.type = LoginType.QRCODE
            lReq.keepLoggedIn = data['keepLoggedIn']
            if 'identityProvider' in data:
                lReq.identityProvider = data['identityProvider']
            if 'accessLocation' in data:
                lReq.accessLocation = data['accessLocation']
            if 'systemName' in data:
                lReq.systemName = data['systemName']
            lReq.verifier = data['verifier']
            lReq.e2eeVersion = data['e2eeVersion']
        else:
            lReq=False
        return lReq

    def loginWithCredential(self, _id, passwd):
        if self.systemName is None:
            self.systemName=self.server.SYSTEM_NAME
        if self.server.EMAIL_REGEX.match(_id):
            self.provider = IdentityProvider.LINE       # LINE
        else:
            self.provider = IdentityProvider.NAVER_KR   # NAVER

        if self.appName is None:
            self.appName=self.server.APP_NAME
        self.server.setHeaders('X-Line-Application', self.appName)
        self.tauth = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_AUTH_QUERY_PATH).Talk(isopen=False)

        rsaKey = self.tauth.getRSAKeyInfo(self.provider)
        
        message = (chr(len(rsaKey.sessionKey)) + rsaKey.sessionKey +
                   chr(len(_id)) + _id +
                   chr(len(passwd)) + passwd).encode('utf-8')
        pub_key = rsa.PublicKey(int(rsaKey.nvalue, 16), int(rsaKey.evalue, 16))
        crypto = rsa.encrypt(message, pub_key).hex()

        try:
            with open(_id + '.crt', 'r') as f:
                self.certificate = f.read()
        except:
            if self.certificate is not None:
                if os.path.exists(self.certificate):
                    with open(self.certificate, 'r') as f:
                        self.certificate = f.read()

        self.auth = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_LOGIN_QUERY_PATH).Auth(isopen=False)

        lReq = self.__loginRequest('0', {
            'identityProvider': self.provider,
            'identifier': rsaKey.keynm,
            'password': crypto,
            'keepLoggedIn': self.keepLoggedIn,
            'accessLocation': self.server.IP_ADDR,
            'systemName': self.systemName,
            'certificate': self.certificate,
            'e2eeVersion': 0
        })

        result = self.auth.loginZ(lReq)
        
        if result.type == LoginResultType.REQUIRE_DEVICE_CONFIRM:
            self.callback.PinVerified(result.pinCode)

            self.server.setHeaders('X-Line-Access', result.verifier)
            getAccessKey = self.server.getJson(self.server.parseUrl(self.server.LINE_CERTIFICATE_PATH), allowHeader=True)

            self.auth = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_LOGIN_QUERY_PATH).Auth(isopen=False)

            try:
                lReq = self.__loginRequest('1', {
                    'keepLoggedIn': self.keepLoggedIn,
                    'verifier': getAccessKey['result']['verifier'],
                    'e2eeVersion': 0
                })
                result = self.auth.loginZ(lReq)
            except:
                raise Exception('Login failed')
            
            if result.type == LoginResultType.SUCCESS:
                if result.certificate is not None:
                    with open(_id + '.crt', 'w') as f:
                        f.write(result.certificate)
                    self.certificate = result.certificate
                if result.authToken is not None:
                    self.loginWithAuthToken(result.authToken)
                else:
                    return False
            else:
                raise Exception('Login failed')

        elif result.type == LoginResultType.REQUIRE_QRCODE:
            self.loginWithQrCode()
            pass

        elif result.type == LoginResultType.SUCCESS:
            self.certificate = result.certificate
            self.loginWithAuthToken(result.authToken)

    def loginWithQrCode(self):
        if self.systemName is None:
            self.systemName=self.server.SYSTEM_NAME
        if self.appName is None:
            self.appName=self.server.APP_NAME
        self.server.setHeaders('X-Line-Application', self.appName)

        self.tauth = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_AUTH_QUERY_PATH).Talk(isopen=False)
        qrCode = self.tauth.getAuthQrcode(self.keepLoggedIn, self.systemName)

        if self.e2ee:
            params = self._e2ee.generateParams()
            self.callback.QrUrl('https://line.me/R/au/q/%s?%s' % (qrCode.verifier, params), self.showQr)
        else:
            self.callback.QrUrl('https://line.me/R/au/q/' + qrCode.verifier, self.showQr)
        self.server.setHeaders('X-Line-Access', qrCode.verifier)

        getAccessKey = self.server.getJson(self.server.parseUrl(self.server.LINE_CERTIFICATE_PATH), allowHeader=True)
        if self.e2ee:
            public_key = getAccessKey['result']['metadata']['publicKey']
            encrypted_keychain = getAccessKey['result']['metadata']['encryptedKeyChain']
            hash_keychain = getAccessKey['result']['metadata']['hashKeyChain']
            keychain_data = self._e2ee.decryptKeychain(encrypted_keychain, public_key)
            print ('Public Key :', public_key)
            print ('Encrypted Keychain :', encrypted_keychain)
            print ('Hash Keychain :', hash_keychain)
            print ('Keychain Data :', keychain_data)

        self.auth = Session(self.server.LINE_HOST_DOMAIN, self.server.Headers, self.server.LINE_LOGIN_QUERY_PATH).Auth(isopen=False)

        try:
            lReq = self.__loginRequest('1', {
                'keepLoggedIn': self.keepLoggedIn,
                'systemName': self.systemName,
                'identityProvider': IdentityProvider.LINE,
                'verifier': getAccessKey['result']['verifier'],
                'accessLocation': self.server.IP_ADDR,
                'e2eeVersion': 1 if self.e2ee else 0
            })
            result = self.auth.loginZ(lReq)
        except:
            raise Exception('Login failed')

        if result.type == LoginResultType.SUCCESS:
            if result.authToken is not None:
                self.loginWithAuthToken(result.authToken)
            else:
                return False
        else:
            raise Exception('Login failed')

    # def loginWithQrCodeV2(self,certificate=None):
    #     if self.systemName is None:
    #         self.systemName=self.server.SYSTEM_NAME
    #     if self.appName is None:
    #         self.appName=self.server.APP_NAME
    #     if certificate:
    #         self.certificate = certificate
    #     session_id = self.create_qrcode_session()
    #     url = self.create_qrcode(session_id)
    #     secret = self.create_secret()
    #     self.callback.QrUrl(url+secret,False)
    #     pincode = self.check_qrcode_and_verify_certificate(session_id,self.certificate)
    #     if pincode:
    #         self.callback.PinVerified(pincode)
    #         self.check_pincode(session_id)
    #     response = self.login_with_qrcode_request(session_id, self.systemName)
    #     getAccessKey = self.server.getJson(self.server.parseUrl(self.server.LINE_CERTIFICATE_PATH), allowHeader=True)
    #     print(getAccessKey)
    #     print(response)
    #     self.certificate = response.certificate
    #     # self.loginWithAuthToken(response.accessToken)

    # def genTokenV2(self,session_id):
    #     self.check_pincode(session_id)
    #     response = self.login_with_qrcode_request(session_id, self.systemName)
    #     return response

    # def __get_transport(self, url: str, client: Optional[HTTPClient] = None) -> THttpClient:
    #     if client:
    #         return THttpClient(url, self.to_dict(), 30, client=client)
    #     else:
    #         return THttpClient(url, self.to_dict(), 30)

    # def create_qrcode_session(self) -> str:
    #     self.lr = self.create_secondary_qr_code_login_service_client()
    #     return self.lr.createSession(CreateQrSessionRequest()).authSessionId

    # def create_qrcode(self, session_id: str) -> str:
    #     return self.lr.createQrCode(CreateQrCodeRequest(session_id)).callbackUrl

    # def check_qrcode_and_verify_certificate(self, session_id: str, certificate: Optional[str]) -> Optional[str]:
    #     self.set_access_token("")
    #     self.lc = self.create_secondary_qr_code_login_permit_notice_service_client()
    #     self.lc.checkQrCodeVerified(CheckQrCodeVerifiedRequest(session_id))

    #     try:
    #         self.lr.verifyCertificate(VerifyCertificateRequest(session_id, certificate))
    #         return None
    #     except:
    #         return self.lr.createPinCode(CreatePinCodeRequest(session_id)).pinCode

    # def check_pincode(self, session_id: str):
    #     self.lc.checkPinCodeVerified(CheckPinCodeVerifiedRequest(session_id))

    # def login_with_qrcode_request(self, session_id: str, system_name: str) -> QrCodeLoginResponse:
    #     return self.lr.qrCodeLogin(QrCodeLoginRequest(session_id, system_name, autoLoginIsRequired=True))

    # def create_secret(self):
    #     private_key = curve.generatePrivateKey(os.urandom(32))
    #     public_key = curve.generatePublicKey(private_key)

    #     secret = urllib.parse.quote(base64.b64encode(public_key).decode())
    #     version = 1
    #     return f"?secret={secret}&e2eeVersion={version}"

    # def create_session(self, url: str,service_client, http_client: Optional[HTTPClient] = None):
    #     trans = self.__get_transport(url, http_client)
    #     proto = TCompactProtocolAccelerated(trans)

    #     return service_client(proto)

    # def set_access_token(self, access_token: str):
    #     self.access_token = access_token

    # def to_dict(self) -> Dict[str, str]:
    #     headers = {
    #         "User-Agent": self.server.USER_AGENT,
    #         "X-Line-Application": self.server.APP_NAME,
    #         "x-lal": "en_US",
    #     }

    #     if self.access_token is not None:
    #         headers["X-Line-Access"] = self.access_token

    #     return headers

    # def create_secondary_qr_code_login_service_client(self) -> SecondaryQrCodeLoginService.Client:
    #     return self.create_session(self.server.LINE_SECONDARY_LOGIN_REQUEST_V1, SecondaryQrCodeLoginService.Client, self.__client)

    # def create_secondary_qr_code_login_permit_notice_service_client(self) -> SecondaryQrCodeLoginPermitNoticeService.Client:
    #     return self.create_session(self.server.LINE_SECONDARY_LOGIN_CHECK_V1, SecondaryQrCodeLoginPermitNoticeService.Client, self.__client)


    def loginWithAuthToken(self, authToken=None):
        if authToken is None:
            raise Exception('Please provide Auth Token')
        if self.appName is None:
            self.appName=self.server.APP_NAME
        self.server.setHeadersWithDict({
            'X-Line-Application': self.appName,
            'X-Line-Access': authToken
        })
        self.authToken = authToken
        self.__loadSession()

    def __defaultCallback(self, str):
        print(str)

    def logout(self):
        self.isLogin = False
        self.auth.logoutZ()