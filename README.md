## Info

This repo contains projects to support the "Okta for Red Teamers" blog post [here](https://www.trustedsec.com/?p=30372).

## Cloud-Nine

An Okta Agent tool which emulates an AD Agent, allows interception of authentication requests, and adding a skeleton key.

### Installation

```
python3 -m venv env
source ./env/bin/activate
pip install -r requirements.txt
```

### Usage

Two modes are supported:

1. Use an stolen AD Agent token to connect to Okta and intercept authentication requests:

```bash
python ./main.py --tenant-domain example.okta.com --skeleton-key WibbleWobble99 token --api-token 0023452Lllk2KqjLBvaxANWEgTd7bqjsxjo8aZj0wd --app-id 0oa7c027u2TcJxoki697 --agent-id a537cnm9ldwPILkqP697
```

2. Register a new AD Agent with Okta and intercept authentication requests:

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

