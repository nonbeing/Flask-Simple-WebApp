from flask import render_template, request
from app import app
import hashlib
import hmac
import time
import os
from slacker import Slacker


CLIENT_ID = "20006151314.70868885203"
CLIENT_SECRET = "07a40f40126b4ce167c36c39e80411f1"
SIG_FILE_PATH = "./tmp/sig"
REDIRECT_URI = "http://nonbeing.tech/oauth"

with open(os.path.join(os.path.dirname(__file__), 'SLACK_BOT_API_TOKEN')) as f:
    BOT_API_TOKEN = f.read().strip()
slack = Slacker(BOT_API_TOKEN)

with open(os.path.join(os.path.dirname(__file__), 'HMAC_SECRET_KEY')) as f:
    _HMAC_KEY = f.read().strip()

def _hmac_sha256(message, key=_HMAC_KEY):
    # Generate the hash.
    signature = hmac.new(
        key,
        str(message),
        hashlib.sha256
    ).hexdigest()

    return signature



@app.route('/')
@app.route('/index')
def index():
    now_ts = time.time()
    signature = _hmac_sha256(now_ts)

    # save the signature for later
    # TODO: needs to go into a db, even sqlite will do
    with open(SIG_FILE_PATH, 'a') as f:
        f.write("{}\n".format(signature))

    return render_template("index.html",
        client_id=CLIENT_ID,
        title='Home',
        signature=signature,
        redirect_uri=REDIRECT_URI)



@app.route('/oauth')
def oauth():
    code = request.args.get('code')
    if code:
        response = slack.oauth.access(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, code=code)
    else:
        return "ERROR: no code!"
    return response


# ZeroSSL challenges:
# @app.route('/.well-known/acme-challenge/mdaDswXLn73yN8Zv8Kfoxoa8R7k2Lg7fgAhobwne1Ig')
# def challenge1():
#     return "mdaDswXLn73yN8Zv8Kfoxoa8R7k2Lg7fgAhobwne1Ig.LwhNiXeAtyFQtGtYKfpys8KYzU4VM2XBtVVVk37d6Kw"


# @app.route('/.well-known/acme-challenge/NP1ijvAqlJArbOwWazhfnSs9PPcioYcn7dq_Jzsk9K4')
# def challenge2():
#     return "NP1ijvAqlJArbOwWazhfnSs9PPcioYcn7dq_Jzsk9K4.LwhNiXeAtyFQtGtYKfpys8KYzU4VM2XBtVVVk37d6Kw"


