import base64
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import urllib
from flask import Flask, url_for, session, request, jsonify
from flask import redirect, render_template
from flask_oauthlib.client import OAuth


app = Flask(__name__, template_folder='templates')
app.config.from_pyfile('application.cfg', silent=False)
oauth = OAuth(app)

remote = oauth.remote_app(
    'TrueNTH Central Services',
    consumer_key=app.config['CLIENT_ID'],
    consumer_secret=app.config['CLIENT_SECRET'],
    request_token_params={'scope': 'email'},
    base_url=app.config['BASE_URL'],
    request_token_url=None,
    access_token_url=app.config['ACCESS_TOKEN_URL'],
    authorize_url=app.config['AUTHORIZE_URL'],
)

@app.route('/enrollment/complete')
def complete():
    return jsonify(message='successful next route to /enrollment/complete',
                   code=request.args.get('code'))

@app.route('/code', methods=['GET', 'POST'])
def code():
    if request.method == 'POST':
        next_url = 'http://truenth-intervention-demo.cirg.washington.edu:8000/enrollment/complete?code={}'.format(request.form['code'])
        target = 'http://truenth-demo.cirg.washington.edu:5000/user/register?next={}'.format(urllib.quote(next_url))
        app.logger.debug("redirecting to {}".format(target))
        return redirect(target)
    else:
        return render_template('code.html')

def validate_remote_token():
    """Make a protected call to the remote API to validate token

    Return True if valid, False otherwise
    """
    if 'remote_oauth' not in session:
        return False

    token_status = remote.get('../oauth/token-status')

    if token_status.status == 200:
        app.logger.debug("token status: %s", str(token_status.data))
        return True
    else:
        app.logger.debug("validate_remote_token >>> remote call failed with status: %d",
                token_status.status)
    return False


@app.route('/login')
def login():
    """Entry point for intiating OAuth 2 authentication dance

    Goal is to obtain a valide OAuth 2 access token from Central
    Services.  It will be stored in the local session (cookie based)
    as 'remote_oauth'.

    Details of obtaining the token are hidden in `flask_oauthlib.client`
    initiated here with a call to remote.authorize()

    """
    if validate_remote_token():
        return redirect('/')

    # Still here means we need to (re)authorize this intervention as an
    # OAuth client against Central Services.
    next_url = request.args.get('next') or request.referrer or request.url
    app.logger.debug(">>> remote call to authorize with next=%s", next_url)
    return remote.authorize(
        callback=url_for('authorized' , _external=True),
        next=next_url
    )


@app.route('/')
def index():
    authorized = validate_remote_token()

    if authorized:
        login_url = None
        token = session['remote_oauth']
        demographics = remote.get('demographics').data
    else:
        login_url = urllib.quote("http://{0}{1}".\
                format(app.config['SERVER_NAME'], url_for('login')))
        token = demographics = None

    return render_template('client_home.html', authorized=authorized,
            PORTAL=app.config['PORTAL'], demographics=demographics,
            TOKEN=token, login_url=login_url)

@app.route('/logevent', methods=('GET', 'POST'))
def logevent():
    if request.method == 'POST':
        message = request.form.get('message')
        resp = remote.post('auditlog', data={'message': message})
        return jsonify(result=resp.data)
    return render_template('logevent.html', PORTAL=app.config['PORTAL'],
            TOKEN=session['remote_oauth'])


@app.route('/authorized')
def authorized():
    resp = remote.authorized_response()
    if resp is None:
        message = 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
        app.logger.error(message)
        return message
    session['remote_oauth'] = (resp['access_token'], '')
    app.logger.info("got access_token %s", resp['access_token'])
    session['remote_oauth_expires_at'] = datetime.utcnow() +\
            timedelta(0, resp['expires_in'])
    app.logger.info("expires_in %s", resp['expires_in'])

    # Redirect to the next parameter, if provided
    if request.args.get('next'):
        app.logger.info("done with auth, redirect to 'next': %s",
                        request.args.get('next'))
        return redirect(request.args.get('next'))
    return redirect('/')


@app.route('/remote-oauth-token')
def remote_oauth_token():
    "Simple access for JS use of current Bearer token in session cookie"
    if 'remote_oauth' not in session:
        return jsonify(error='not authenticated')
    return jsonify(Bearer=session['remote_oauth'])


@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


@app.route('/callback', methods=('POST',))
def CS_callback():
    """Register this endpoint with Central Services for event callbacks

    Central Services will POST a signed_request on significant events
    such as user logout.

    Verify the signature and log the event.

    """
    def base64_url_decode(s):
        """url safe base64 decoding method"""
        padding_factor = (4 - len(s) % 4)
        s += "="*padding_factor
        return base64.b64decode(unicode(s).translate(
            dict(zip(map(ord, u'-_'), u'+/'))))

    encoded_sig, payload = request.form['signed_request'].split('.')
    sig = base64_url_decode(encoded_sig)
    data = base64_url_decode(payload)

    secret = app.config['CLIENT_SECRET']
    expected_sig = hmac.new(secret, msg=payload,
            digestmod=hashlib.sha256).digest()
    if expected_sig != sig:
        app.logger.error("Invalid signature from Central Services!")
        return jsonify(error='bad signature')

    data = json.loads(data)
    app.logger.debug('event: %s for user %d, refresh_token %s', data['event'],
        data['user_id'], data['refresh_token'])

    return jsonify(message='ok')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    print "Starting with client_id", app.config['CLIENT_ID']
    app.run(host='0.0.0.0', port=8000, threaded=True)
