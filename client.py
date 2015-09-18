import base64
import hashlib
import hmac
import json
from flask import Flask, url_for, session, request, jsonify
from flask import redirect, render_template
from flask_oauthlib.client import OAuth

app = Flask(__name__, template_folder='templates')
app.config.from_pyfile('application.cfg', silent=False)
oauth = OAuth(app)

remote = oauth.remote_app(
    'remote',
    consumer_key=app.config['CLIENT_ID'],
    consumer_secret=app.config['CLIENT_SECRET'],
    request_token_params={'scope': 'email'},
    base_url=app.config['BASE_URL'],
    request_token_url=None,
    access_token_url=app.config['ACCESS_TOKEN_URL'],
    authorize_url=app.config['AUTHORIZE_URL'],
)


@app.route('/')
def index():
    if 'remote_oauth' in session:
        # Waiting on clinical parsing and display
        # clinical = remote.get('clinical')
        demographics = remote.get('demographics')
        if demographics.status == 200: 
            return render_template('client_home.html',
                PORTAL=app.config['PORTAL'],
                demographics=demographics.data,
                TOKEN=session['remote_oauth'])

    # Still here means we need to (re)authorize this intervention as an
    # OAuth client to the Portal.
    next_url = request.args.get('next') or request.referrer or request.url
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )


@app.route('/authorized')
def authorized():
    resp = remote.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['remote_oauth'] = (resp['access_token'], '')
    app.logger.info("got access_token %s", resp['access_token'])
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
    app.logger.debug('event: %s for user %d', data['event'],
        data['user_id'])

    return jsonify(message='ok')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    print "Starting with client_id", app.config['CLIENT_ID']
    app.run(host='0.0.0.0', port=8000)
