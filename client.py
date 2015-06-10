from flask import Flask, url_for, session, request, jsonify, redirect, render_template
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
    # TODO: Need to validate remote_oauth - problems w/ expired
    if 'remote_oauth' in session:
        resp = remote.get('me')
        resp2 = remote.get('assessments')
        #return jsonify(resp.data)
	return render_template('client_home.html', PORTAL=app.config['PORTAL'],
            data=resp.data, assessments=resp2.data)

    # Without 'remote_oauth' in session, we haven't yet authorized
    # this intervention as an OAuth client to the Portal.  Do so now:
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
    #return jsonify(oauth_token=resp['access_token'])
    return redirect('/')

@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    print "Starting with client_id", app.config['CLIENT_ID']
    app.run(host='0.0.0.0', port=8000)
