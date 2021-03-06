from flask import render_template, request, redirect
from app import app
import hashlib
import hmac
import time
import os
from slacker import Slacker
import json
import logging
from logging.handlers import RotatingFileHandler
import boto3
from botocore.exceptions import ParamValidationError, ClientError
import ConfigParser


# create file logger
logger = logging.getLogger('flask_webapp')
logger.setLevel(logging.DEBUG)
fileHandler = RotatingFileHandler("/tmp/flaskwebapp.log", maxBytes=(1048576*5), backupCount=3)
fileHandler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
fileHandler.setFormatter(formatter)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(formatter)
logger.addHandler(fileHandler)
logger.addHandler(consoleHandler)

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
APP_OAUTH_END_URI = config.get('webapp', 'APP_OAUTH_END_URI')
APP_SIG_FILE_PATH = config.get('webapp', 'APP_SIG_FILE_PATH')
AWS_REGION = config.get('aws', 'AWS_REGION')

slack = Slacker(SLACK_BOT_API_TOKEN)

# get global DynamoDB client
# it's assumed that the EC2 instance running this code has an associated Instance Profile (IAM Role)
# that has suitable DynamoDB permissions --> hence no API keys need to specified here
session = boto3.Session(region_name=AWS_REGION)
dynamodb = session.resource('dynamodb')


def _hmac_sha256(message, key=APP_HMAC_KEY):
    # Generate the hmac-sha256 hash
    signature = hmac.new(
        key,
        str(message),
        hashlib.sha256
    ).hexdigest()

    logger.info("signature for '{}' is: '{}'".format(message, signature))
    return signature


def _put_dynamodb_item(dynamodb_table_name, item):
    table = dynamodb.Table(dynamodb_table_name)
    dynamodb_response = table.put_item( Item=item )

    logger.info("DynamoDB PutItem Response:\n{}".format(json.dumps(dynamodb_response, indent=4)))


def _get_dynamodb_item(dynamodb_table_name, key):
    table = dynamodb.Table(dynamodb_table_name)

    try:
        dynamodb_response = table.get_item( Key=key )
    except ParamValidationError as e:
        logger.error("DynamoDB returned a ParamValidationError error: '{}'".format(e))
        return None
    except ClientError as e:
        logger.error("DynamoDB returned a ClientError error: '{}'".format(e))
        return None

    logger.info("DynamoDB GetItem Response:\n{}".format(json.dumps(dynamodb_response, indent=4)))

    if "Item" in dynamodb_response.keys():
        return dynamodb_response['Item']
    else:
        logger.error("DynamoDB did not retrieve an item corresponding to key: '{}'".format(key))
        return None


def _update_dynamodb_item(dynamodb_table_name, key, update_expression, exp_values, return_values="UPDATED_NEW"):
    table = dynamodb.Table(dynamodb_table_name)
    dynamodb_response = table.update_item( Key=key, UpdateExpression=update_expression, ExpressionAttributeValues=exp_values, ReturnValues=return_values )

    logger.info("DynamoDB UpdateItem Response:\n{}".format(json.dumps(dynamodb_response, indent=4)))


def _do_oauth(redirect_uri=None):
    flask_url = request.url_rule

    # grab the 'code' and 'state' from the incoming Slack request
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    retval = slack_response = {}
    # TODO: Verify that state is the same as was sent to us initially
    # STATE VERIFICATION STEPS
    logger.info("do_oauth(): code: '{}', state: '{}', redirect_uri: '{}'".format(code, state, redirect_uri))

    try:
        if code: #'code' implies 'happy path scenario': the user approved the slack scopes asked of him
            logger.info("Got 'code' from Slack, doing slack.oauth.access() with client_id:{}, client_secret:{}, code:{}, redirect_uri:{}".format(SLACK_CLIENT_ID, SLACK_CLIENT_SECRET, code, redirect_uri))

            # exchange 'code' for an access token as per Slack Oauth API
            slack_response = slack.oauth.access(client_id=SLACK_CLIENT_ID, client_secret=SLACK_CLIENT_SECRET, code=code, redirect_uri=redirect_uri)

            logger.info("Slack Oauth response for code='{}': body: {}, error: {}, successful: {}".format(code, slack_response.body, slack_response.error, slack_response.successful))
            oauth_json = slack_response.body

            if oauth_json['ok']:
                # user_name isn't in the slack_response for "Add To Slack" flow; have to do auth.test() to get it:
                logger.info("Calling slack auth.test() to get user_id and for sanity checks".format())
                slack_client = Slacker(oauth_json['access_token'])
                test_response = slack_client.auth.test()

                if test_response.successful:
                    user_name = test_response.body['user']
                    logger.info("auth.test(): got 'user_name' = '{}'".format(user_name))

                    dynamo_item = { 'team_id': oauth_json['team_id'], 'team_name': oauth_json['team_name'], 'installing_user_id': oauth_json['user_id'], 'user_name': user_name, 'slack_scope': oauth_json['scope'], 'access_token': oauth_json['access_token'], 'bot_access_token': oauth_json['bot']['bot_access_token'], 'bot_user_id': oauth_json['bot']['bot_user_id'], 'ok': oauth_json['ok'] }

                    logger.info("_do_oauth(): dynamo_item being put: '{}'".format(dynamo_item))
                    _put_dynamodb_item(APP_DYNAMODB_TABLE, dynamo_item)

                    retval['user_name'] = user_name
                    retval['team_name'] = oauth_json['team_name']
                else:
                    retval['error_html' ] = render_template("error.html", error_type="Slack Auth Test", description="We're sorry, but your Slack Authorization Token is invalid", details="auth.test() failed... {}".format(test_response.body))
            else:
                retval['error_html'] = render_template("error.html", error_type="OauthNotOk", description="We're sorry, but your Slack Authorization Flow somehow failed", details="{}".format(slack_response.body))
        else:
            logger.error("Incoming request to /oauth was missing the expected 'code' param, error-from-slack:'{}'".format(error))
            retval['error_html'] = render_template("error.html", error_type="Oauth", description="We're sorry, but your Slack Authorization Flow failed", details="missing 'code' param from Slack, error-from-slack:{}".format(error))
    except Exception as e:
        logger.error("General Exception: '{}'".format(str(e)))
        retval['error_html'] = render_template("error.html", error_type="Bad Code", description="Sorry, something went wrong. Please report bug to `admin AT nonbeing.tech`", details="General Exception: '{}'".format(str(e)))
    return retval


@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html", title="Welcome to OpsBot", client_id=SLACK_CLIENT_ID, redirect_uri=APP_OAUTH_END_URI)


@app.route('/oauthEnd')
def slack_oauth_end():
    logger.info("slack_oauth_end() - going to do oauth")
    retval = _do_oauth(redirect_uri=APP_OAUTH_END_URI)

    if 'error_html' in retval.keys():
        return retval['error_html']

    # all went well, take user to end-of-flow success page
    return render_template("success.html", user_name=retval['user_name'], team_name=retval['team_name'])



# Help/Support page: just redirect to index for now
@app.route('/opsbot/help')
def opsbot_help():
    return redirect("http://nonbeing.tech", code=302)
