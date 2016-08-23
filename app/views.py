from flask import render_template, request, redirect
from app import app
import hashlib
import hmac
import time
import os
from slacker import Slacker
import json
import logging
import boto3
import ConfigParser

# create file logger
logger = logging.getLogger('flask_webapp')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("/tmp/flaskwebapp.log")
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

# Parse config/SECRETS.ini file - which must be created by hand
config = ConfigParser.ConfigParser()
config_file = os.path.join(os.path.dirname(__file__), 'config/SECRETS.ini')
logger.info("config_file full path:'{}'".format(config_file))
config.read(config_file)
logger.info("config sections: {}".format(config.sections()))

# Read global consts from config
SLACK_CLIENT_ID = config.get('slack', 'SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = config.get('slack', 'SLACK_CLIENT_SECRET')
SLACK_BOT_API_TOKEN = config.get('slack', 'SLACK_BOT_API_TOKEN')
APP_DYNAMODB_TABLE = config.get('webapp', 'APP_DYNAMODB_TABLE')
APP_HMAC_KEY = config.get('webapp', 'APP_HMAC_KEY')
APP_SIGN_IN_WITH_SLACK_REDIRECT_URI = config.get('webapp', 'APP_SIGN_IN_WITH_SLACK_REDIRECT_URI')
APP_ADD_TO_SLACK_REDIRECT_URI = config.get('webapp', 'APP_ADD_TO_SLACK_REDIRECT_URI')
APP_SIG_FILE_PATH = config.get('webapp', 'APP_SIG_FILE_PATH')
AWS_REGION = config.get('aws', 'AWS_REGION')

slack = Slacker(SLACK_BOT_API_TOKEN)



def _hmac_sha256(message, key=APP_HMAC_KEY):
    # Generate the hmac-sha256 hash
    signature = hmac.new(
        key,
        str(message),
        hashlib.sha256
    ).hexdigest()

    logger.info("signature for '{}' is: '{}'".format(message, signature))
    return signature



def _add_dynamodb_item(item, dynamodb_table_name):
    session = boto3.Session(region_name=AWS_REGION)
    dynamodb = session.resource('dynamodb')

    table = dynamodb.Table(dynamodb_table_name)

    dynamodb_response = table.put_item(
       Item=item
    )

    logger.info("DynamoDB PutItem Response:\n{}".format(json.dumps(dynamodb_response, indent=4)))



def _do_oauth(signature=None):
    # grab the 'code' and 'state' from the incoming Slack request
    code = request.args.get('code')
    state = request.args.get('state')

    # TODO: Verify that state is the same as was sent to us initially
    # STATE VERIFICATION STEPS
    logger.info("oauth - code: '{}', oauth - state: '{}'".format(code, state))

    try:
        if code: #'code' implies 'happy path scenario': the user approved the slack scopes asked of him
            slack_response = slack.oauth.access(client_id=SLACK_CLIENT_ID, client_secret=SLACK_CLIENT_SECRET, code=code)
            logger.info("Slack Oauth response for code='{}' = {}".format(code, slack_response))
            oauth_json = json.loads(slack_response)

            if oauth_json['ok']:
                dynamo_item = { 'team_id': oauth_json['team_id'], 'team_name': oauth_json['team_name'], 'access_token': oauth_json['access_token'], 'scope': oauth_json['scope'], 'user_id': oauth_json['user_id'], 'bot_user_id': oauth_json['bot']['bot_user_id'], 'bot_access_token': oauth_json['bot']['bot_access_token'], 'ok': oauth_json['ok'], 'signature': signature }

                _add_dynamodb_item(dynamo_item, APP_DYNAMODB_TABLE)
            else:
                return render_template("error.html", error_type="Oauth", description="We're sorry, but your Slack Authorization Flow somehow failed", details="{}".format(slack_response))
        else:
            logger.error("Incoming request to /oauth was missing the expected 'code' param ")
            return render_template("error.html", error_type="Oauth", description="We're sorry, but your Slack Authorization Flow failed because of a missing 'code' param from Slack.", details="{}".format(slack_response))
    except Exception as e:
        logger.error("General Exception: '{}'".format(str(e)))
        return "General Exception: '{}'".format(str(e))


@app.route('/')
@app.route('/index')
def index():
    #TODO: Instead of adding the "Add to Slack" button, have a "Sign into Slack" button here
    # When the user has signed into his team, we can take a hash of the team name instead of an
    # arbitrary, useless hash

    return render_template("index.html", title="Welcome to OpsBot", client_id=SLACK_CLIENT_ID, redirect_uri=APP_SIGN_IN_WITH_SLACK_REDIRECT_URI)



@app.route('/oauthSignInWithSlack')
def slack_oauth_sign_in_with_slack():
    now_ts = time.time()
    signature = _hmac_sha256(now_ts)

    logger.info("now_ts: '{}'\nsignature: '{}'".format(now_ts, signature))

    # save the signature for later
    # TODO: needs to go into a db, even sqlite will do
    with open(APP_SIG_FILE_PATH, 'a') as f:
        f.write("{}\n".format(signature))

    _do_oauth(signature)

    # all went well, take user to AddToSlack flow
    return render_template("addToSlack.html",
        client_id=SLACK_CLIENT_ID,
        title='Install OpsBot',
        signature=signature,
        redirect_uri=APP_ADD_TO_SLACK_REDIRECT_URI)



@app.route('/oauthAddToSlack')
def slack_oauth_add_to_slack():
    _do_oauth()

    # all went well, take user to success endpoint
    return render_template("success.html", description="Thank you for adding OpsBot to your Slack team!")


# Help/Support page: just redirect to index for now
@app.route('/opsbot/help')
def opsbot_help():
    return redirect("http://nonbeing.tech", code=302)

