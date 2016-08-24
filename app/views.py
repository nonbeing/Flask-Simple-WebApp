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



def _do_oauth(signature=None, team=None):
    flask_url = request.url_rule

    # grab the 'code' and 'state' from the incoming Slack request
    code = request.args.get('code')
    state = request.args.get('state')
    redirect_uri = request.args.get('redirect_uri')
    retval = slack_response = {}
    # TODO: Verify that state is the same as was sent to us initially
    # STATE VERIFICATION STEPS
    logger.info("do_oauth(): code: '{}', state: '{}', redirect_uri: '{}'".format(code, state, redirect_uri))

    try:
        if code: #'code' implies 'happy path scenario': the user approved the slack scopes asked of him
            logger.info("Got 'code' from Slack, doing slack.oauth.access()")

            slack_response = slack.oauth.access(client_id=SLACK_CLIENT_ID, client_secret=SLACK_CLIENT_SECRET, code=code, redirect_uri=redirect_uri)
            logger.info("Slack Oauth response for code='{}': body: {}, error: {}, successful: {}".format(code, slack_response.body, slack_response.error, slack_response.successful))
            oauth_json = slack_response.body

            if oauth_json['ok']:
                if 'oauthSignInWithSlack' in flask_url.rule:
                    dynamo_item = { 'team_id': oauth_json['team']['id'], 'installing_user_id': oauth_json['user']['id'], 'user_name': oauth_json['user']['name'], 'scope': oauth_json['scope'], 'access_token': oauth_json['access_token'], 'ok': oauth_json['ok'] }

                    retval['user_name'] = oauth_json['user']['name']

                elif 'oauthAddToSlack' in flask_url.rule:
                    # TODO: get_item() first, then simply add new attributes to existing item
                    dynamo_item = { 'team_id': oauth_json['team_id'], 'team_name': oauth_json['team_name'], 'access_token': oauth_json['access_token'], 'scope': oauth_json['scope'], 'user_id': oauth_json['user_id'], 'bot_user_id': oauth_json['bot']['bot_user_id'], 'bot_access_token': oauth_json['bot']['bot_access_token'], 'ok': oauth_json['ok'], 'signature': signature }

                logger.info("_do_oauth(): dynamo_item: '{}'".format(dynamo_item))
                _add_dynamodb_item(dynamo_item, APP_DYNAMODB_TABLE)
            else:
                retval['error_html'] =  render_template("error.html", error_type="Oauth", description="We're sorry, but your Slack Authorization Flow somehow failed", details="{}".format(slack_response))
        else:
            logger.error("Incoming request to /oauth was missing the expected 'code' param ")
            retval['error_html'] = render_template("error.html", error_type="Oauth", description="We're sorry, but your Slack Authorization Flow failed", details="missing 'code' param from Slack".format(slack_response))
    except Exception as e:
        logger.error("General Exception: '{}'".format(str(e)))
        retval['error_html']= render_template("error.html", error_type="Bad Code", description="Sorry, something went wrong. Please report bug to `admin AT nonbeing.tech`", details="General Exception: '{}'".format(str(e)))

    return retval


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

    retval = _do_oauth(signature)

    if 'error_html' in retval.keys():
        return retval['error_html']
    elif 'user_name' in retval.keys():
        user_name = retval['user_name']

    # all went well, take user to AddToSlack flow
    return render_template("addToSlack.html",
        user_name=user_name,
        client_id=SLACK_CLIENT_ID,
        title='Install OpsBot',
        signature=signature,
        redirect_uri=APP_ADD_TO_SLACK_REDIRECT_URI)



@app.route('/oauthAddToSlack')
def slack_oauth_add_to_slack():
    retval = _do_oauth()

    if 'error_html' in retval.keys():
        return retval['error_html']

    # all went well, take user to success endpoint

    # TODO: add "team=xyz" to the template... get the team_id from DynamoDB
    # can do auth.test to get user_name, look at http://stackoverflow.com/a/32323973/376240
    return render_template("success.html", description="Thank you, {}, for adding OpsBot to your Slack team ({})!".format(user_name, team_name))


# Help/Support page: just redirect to index for now
@app.route('/opsbot/help')
def opsbot_help():
    return redirect("http://nonbeing.tech", code=302)

