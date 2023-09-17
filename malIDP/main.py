from flask import Flask, request, render_template
from lib import saml
import argparse

app = Flask(__name__)
samlHandler = None

@app.route('/saml', methods=['POST'])
def handle_saml():
    
    saml_request = request.form['SAMLRequest']

    return render_template('saml_request.html', saml_request=saml_request)

@app.route('/redirect', methods=['POST'])
def handle_redirect():
    
    saml_request = request.form['SAMLRequest']
    username = request.form['username']
    firstname = request.form['firstname']
    lastname = request.form['lastname']

    decoded = samlHandler.handleSamlRequest(saml_request, username, firstname, lastname)

    return render_template('saml_response.html', saml_response=decoded, redirect_path=samlHandler.ssoURL)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SAML Response Generator')
    parser.add_argument('--cert', help='Path to certificate file', required=True)
    parser.add_argument('--key', help='Path to private key file', required=True)
    parser.add_argument('--metadata', help='Path to metadata file', required=True)
    parser.add_argument('--issuer', help='Issuer name', required=True)
    args = parser.parse_args()

    samlHandler = saml.SAMLHandler(args.cert, args.key, args.metadata, args.issuer)
    samlHandler.parseMetadata()

    app.run(debug=False, port=80)
