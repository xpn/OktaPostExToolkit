import http.client
import urllib.parse
import random
import string
import hashlib
import base64
import re
import json
import pprint
import jwt

class Okta:
    def __init__(self, host):
        self.host = host
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36"

    @staticmethod
    def parseStateToken(state_token):
        # parse the state_token JWT and grab the "keyTypes" in the token which will tell us the prompt that the user is likely to get
        # the keyTypes are the authenticator types that the user has registered
        # the prompt will be the first keyType in the list

        # decode the JWT
        decoded = jwt.decode(state_token, verify=False, options={"verify_signature": False})

        # grab the keyTypes
        key_types = decoded["keyTypes"]
        user_mediation = decoded["userMediation"]
        user_verification = decoded["userVerification"]

        return (key_types, user_mediation, user_verification)      
