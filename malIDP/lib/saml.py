import base64
import io
from lxml import etree
import datetime
from signxml import XMLSigner, XMLVerifier
import string
import random

SAMLResponse = """
"""

class SAMLHandler:
    def __init__(self, certificate_file, key_file, metadata_file, issuer):
        self._metadata_file = metadata_file
        self._certificate_file = certificate_file
        self._key_file = key_file
        self.issuer = issuer

    def parseMetadata(self):
        with open(self._metadata_file, 'r') as f:
            metadata = f.read()

        # Parse XML in metadata
        buf = io.BytesIO(metadata.encode('utf-8'))
        metadataXML = etree.parse(buf)

        # Get the entity ID
        self.entityID = metadataXML.xpath('//md:EntityDescriptor/@entityID', namespaces={'md': 'urn:oasis:names:tc:SAML:2.0:metadata'})[0]

        # Get the SSO URL
        self.ssoURL = metadataXML.xpath('//md:AssertionConsumerService/@Location', namespaces={'md': 'urn:oasis:names:tc:SAML:2.0:metadata'})[0]

        # Get the certificate
        with open(self._certificate_file, "r") as cert, open(self._key_file, "r") as key:
          self._certificate = cert.read()
          self._key = key.read()
    
    def _generateSamlResponse(self, username, firstname='test', lastname='user'):
        
        current_datetime = datetime.datetime.utcnow()
        future_datetime = current_datetime + datetime.timedelta(hours=2)
        past_datetime = current_datetime - datetime.timedelta(hours=2)

        # Format the date and time in the desired format
        formatted_current_datetime = current_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
        formatted_past_datetime = past_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
        formatted_future_datetime = future_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
        assertion_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(42))

        with open('data/okta_response.xml', 'r') as f:
            response_data = f.read()

        # Replace the date and time in the response with the formatted date and time
        response_data = response_data.replace('{timenow}', formatted_current_datetime)
        response_data = response_data.replace('{notbefore}', formatted_past_datetime)
        response_data = response_data.replace('{notafter}', formatted_future_datetime)

        response_data = response_data.replace('{issuer}', self.issuer)
        response_data = response_data.replace('{audience}', self.entityID)
        response_data = response_data.replace('{destination}', self.entityID)
        response_data = response_data.replace('{recipient}', self.ssoURL)
        response_data = response_data.replace('{responseto}', self.entityID)

        response_data = response_data.replace('{firstname}', firstname)
        response_data = response_data.replace('{lastname}', lastname)
        response_data = response_data.replace('{email}', username)

        response_data = response_data.replace('{assertionid}', assertion_id)

        saml_root = etree.fromstring(response_data)
        signed_saml_root = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(saml_root, key=self._key, cert=self._certificate)
        verified_data = XMLVerifier().verify(signed_saml_root, x509_cert=self._certificate).signed_xml
        response_data = etree.tostring(signed_saml_root, encoding='unicode')

        return base64.b64encode(response_data.encode('utf-8')).decode('utf-8')
    
    def handleSamlRequest(self, request, username, firstname='test', lastname='user'):
        # Base64 decode
        samlRequest = base64.b64decode(request)

        # Parse XML in samlRequest
        buf = io.BytesIO(samlRequest)
        samlXML = etree.parse(buf)

        response = self._generateSamlResponse(username, firstname, lastname)
        return response
