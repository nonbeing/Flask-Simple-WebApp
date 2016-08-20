from flask import render_template
from app import app
import hashlib
import hmac
import time
import os

CLIENT_ID = "20006151314.70868885203"

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
    with open('/tmp/sig', 'a') as f:
        f.write("{}\n".format(signature))

    return render_template("index.html",
        client_id=CLIENT_ID,
        title='Home',
        signature=signature)


@app.route('/oauth')
def oauth():
    pass
