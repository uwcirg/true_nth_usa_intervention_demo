import base64
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import requests
import urllib
from flask import Flask, url_for, session, request, jsonify
from flask import abort, redirect, render_template
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
    """Simulate SRs login code approach

    Gather an arbitrary code value from a simple form, and initiate the
    redirection loop - expecting control to finally return to next_url
    """
    if request.method == 'POST':
        next_url = 'http://truenth-intervention-demo.cirg.washington.edu:8000/enrollment/complete?code={}'.format(request.form['code'])
        target = 'http://truenth-demo.cirg.washington.edu:5000/user/register?next={}'.format(urllib.quote(next_url))
        app.logger.debug("redirecting to {}".format(target))
        return redirect(target)
    else:
        return render_template('code.html')

def user_id():
    """grab user_id from demographics and save in session"""
    if 'user_id' in session:
        return session['user_id']
    data = remote.get('demographics').data
    ids = [i['value'] for i in data['identifier'] if i['system'] ==
           'http://us.truenth.org/identity-codes/TrueNTH-identity']
    assert(len(ids) == 1)
    session['user_id'] = ids[0]
    return session['user_id']

def validate_remote_token():
    """Make a protected call to the remote API to validate token

    Return number of remaining seconds remote token is good for.
    Value of zero indicates expired (i.e. not valid).

    """
    if 'remote_oauth' not in session:
        app.logger.info('no remote_oauth in session')
        return 0

    token_status = remote.get('../oauth/token-status')

    if token_status.status == 200:
        app.logger.debug("token status: %s", str(token_status.data))
        expires_in = token_status.data['expires_in']
        assert (expires_in > 0)
        return expires_in
    else:
        app.logger.debug("validate_remote_token >>> remote call failed with status: %d",
                token_status.status)
    return 0


@app.route('/login')
def login():
    """Entry point for intiating OAuth 2 authentication dance

    Goal is to obtain a valid OAuth 2 access token from Central
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
        callback=url_for('authorized', _external=True),
        next=next_url
    )


@app.route('/')
def index():
    include_wisercare_args = False  # set true to see wc experience

    query_args = dict()
    PORTAL_NAV_PAGE = "{PORTAL}/api/portal-wrapper-html/".format(
        PORTAL=app.config['PORTAL'])

    authorized = validate_remote_token()
    if authorized:
        token = session['remote_oauth']
        demographics = remote.get('demographics').data
    else:
        token, demographics = None, None
        query_args['login_url'] = url_for('login', _external=True)
        if include_wisercare_args:
            query_args['brand'] = 'wisercare'
            query_args['disable_links'] = '1'
        PORTAL_NAV_PAGE = '?'.join(
            (PORTAL_NAV_PAGE, urllib.urlencode(query_args)))

    return render_template(
        'client_home.html', authorized=authorized,
        PORTAL=app.config['PORTAL'],
        PORTAL_NAV_PAGE=PORTAL_NAV_PAGE,
        demographics=demographics,
        TOKEN=token)


@app.route('/coredata')
def coredata():
    """Demonstrate use of coredata round trip"""
    authorized = validate_remote_token()
    if not authorized:
        app.logger.debug("Not authorized in coredata, redirect")
        return redirect('/')

    def race_eth_from_demographics(demographics):
        # return race & ethnicities or None from demographics data
        if 'extension' not in demographics:
            return None, None

        race = eth = None
        for ext in demographics['extension']:
            if ext['url'] ==\
               'http://hl7.org/fhir/StructureDefinition/us-core-race':
                race = [coding['display'] for coding in
                        ext['valueCodeableConcept']['coding']]
            if ext['url'] ==\
               'http://hl7.org/fhir/StructureDefinition/us-core-ethnicity':
                eth = [coding['display'] for coding in
                        ext['valueCodeableConcept']['coding']]
        return race, eth

    def fetch_procs():
        # return list of procedures in readable format
        data = remote.get('patient/{}/procedure'.format(user_id())).data
        procedures = []
        for entry in data['entry']:
            procedures.append("{} at {}".format(
                entry['content']['code']['coding'][0]['display'],
                entry['content']['performedDateTime']))
        return procedures

    demo = remote.get('demographics').data
    race, eth = race_eth_from_demographics(demo)
    procedures = fetch_procs()
    if race and eth and procedures:
        return render_template(
            'coredata.html', PORTAL=app.config['PORTAL'],
            TOKEN=session['remote_oauth'], race=';'.join(race),
            ethnicity=';'.join(eth),
            procedures=';'.join(procedures),
            args=request.args)
    else:
        # Redirect to Shared Services to acquire race data, asking to
        # be returned to here.
        return_url = url_for('coredata', q_arg1='first_arg',
                             q_arg2='second_arg', _external=True)
        return_url += '&q_arg3=["race","ethnicity"]'
        query = [('next', return_url)]
        # Require only what we don't already have
        if not race:
            query.append(('require', 'race'))
        if not eth:
            query.append(('require', 'ethnicity'))
        if not procedures:
            query.append(('require', 'procedure'))
        target = '{}coredata/acquire?{}'.format(remote.base_url,
                                        urllib.urlencode(query))
        return redirect(target)

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


def service_request(url, method='GET', payload=None, files=None):
    """Wrap server side request with the configured service token """

    base_url = app.config['BASE_URL']
    token = app.config['SERVICE_TOKEN']
    headers = {'Authorization': "Bearer {}".format(token)}

    # relative url with '../' doesn't work, fix if necessary
    endpoint = os.path.join(base_url, url)
    if url.startswith('../'):
        base, junk = os.path.split(base_url[:-1])
        endpoint = os.path.join(base, url[3:])

    if method == 'GET':
        result = requests.get(endpoint, headers=headers)
    elif method == 'POST':
        result = requests.post(
            endpoint, json=payload, headers=headers, files=files)
    elif method == 'PUT':
        result = requests.put(endpoint, json=payload, headers=headers)
    else:
        raise ValueError("unknown method {}".format(method))

    if result.status_code == 200:
        return result.json()
    else:
        app.logger.error(
            "non 200 response on {method} {url} : {message}".format(
                method=method, url=url, message=result.text))
        abort(result.status_code, result.text)


@app.route('/account', methods=['GET', 'POST'])
def account():
    """Simulate new account flow.

    Gather bits from simple form, use service token to generate
    account and set values before logging new user in.

    """
    if request.method == 'POST':
        app.logger.debug(
            "calling creating_account with {}".format(request.form))
        return create_account(**request.form.to_dict())
    else:
        return render_template('account.html')


def create_account(**kwargs):
    """Create remote account using service token"""


    # validate service token
    token_status = service_request('../oauth/token-status')
    assert token_status.get('expires_in') > 0

    # create a new account with given args
    org = None
    if kwargs.get('organization_id'):
        org = {'organizations':[
            {'organization_id': kwargs.get('organization_id')}]}
    user_id = service_request('account', payload=org, method='POST').get(
        'user_id')

    roles = [
        {'name': r} for r in (
            'access_on_verify', 'patient',
            'promote_without_identity_challenge', 'write_only')
        if kwargs.get(r)]
    if roles:
        results = service_request(
            'user/{}/roles'.format(user_id),
            payload={'roles': roles}, method='PUT')
        assert(len(results['roles']) == len(roles))

    # add demographics to new account
    demographics = {"resourceType": "Patient",
                    "name": {"family": kwargs.get('last_name'),
                             "given": kwargs.get('first_name')},
                    "birthDate": kwargs['dob'],
                    "telecom": [
                        {"system": "email", "value": kwargs.get('email')}
                    ],
                   }

    if kwargs.get('practitioner_npi'):
        refs = []
        refs.append({
            "reference":
                "practitioner/{}?system=http://hl7.org/fhir/sid/us-npi".format(
                    kwargs.get('practitioner_npi')
                )})
        if kwargs.get('organization_id'):
            refs.append({
                "reference":
                    "organization/{}".format(kwargs.get('organization_id'))
            })
        demographics['careProvider'] = refs
    results = service_request(
        'demographics/{}'.format(user_id), payload=demographics, method='PUT')

    if kwargs.get('consent'):
        # Post consent to same organization
        org_id = kwargs.get('organization_id')
        assert (org_id)
        d = {'organization_id': org_id, 'agreement_url': 'http://phoney.org'}
        results = service_request('user/{}/consent'.format(user_id), method='POST', payload=d)

    if kwargs.get('biopsy'):
        # Avoiding shortcut 'biopsy' API to simulate MUSIC's use
        d = {
            'resourceType': 'Observation',
            'code': {"coding": [{"code": "111", "system": "http://us.truenth.org/clinical-codes"}]},
            'issued': "2018-03-17",
            'valueQuantity': {'units': 'boolean', 'value': 1}}
        results = service_request(
            'patient/{}/clinical'.format(user_id), method='POST', payload=d)

    if kwargs.get('pca'):
        d = {'value': 'true'}
        results = service_request(
            'patient/{}/clinical/pca_diag'.format(user_id), method='POST', payload=d)

    if kwargs.get('localized'):
        d = {'value': 'true'}
        results = service_request(
            'patient/{}/clinical/pca_localized'.format(user_id), method='POST', payload=d)

    if kwargs.get('procedure'):
        d = {
            'resourceType': "Procedure",
            'subject': {'reference': "Patient/{}".format(user_id)},
            'code': {'coding': [{"code": "999", "system": "http://us.truenth.org/clinical-codes"}]},
            'performedDateTime': "2018-03-16"}
        results = service_request(
            'procedure', method='POST', payload=d)

    if kwargs.get('intervention_access'):
        # grant user access to the named intervention
        data = {'access': 'granted', 'user_id': user_id}
        results = service_request(
            'intervention/{i_name}'.format(
                i_name=kwargs.get('intervention_access')), payload=data, method='PUT')
    if kwargs.get('post_user_doc'):
        # grant user access to the named intervention
        pdf = open('/tmp/worldcookery.pdf', 'rb')
        results = service_request(
            'user/{user_id}/patient_report'.format(
                user_id=user_id), files={'file': pdf}, method='POST')

    if kwargs.get('access_url'):
        # generate access url and redirect to that target
        results = service_request('user/{}/access_url'.format(user_id))
        return redirect(results.get('access_url'))
    else:
        # generate invite email and display contents
        results = service_request(
            url='user/{}/invite?preview=True'.format(user_id), method='POST')
        return jsonify(results=results)


@app.route('/auth_suspend_queries')
def auth_suspend_queries():
    """Simulate new account registration using `suspend_initial_queries` """

    # confirm we're not already in auth state
    assert not validate_remote_token()

    # authorize this intervention as an OAuth client against Central Services.
    # user will be asked to login or register
    # including the suspend_initial_queries flag
    next_url = request.args.get('next') or request.referrer or request.url
    app.logger.debug(">>> remote call to authorize with next=%s", next_url)
    return remote.authorize(
        callback=url_for('authorized', _external=True),
        next=next_url,
        suspend_initial_queries=True)


@app.route('/register-now')
def registernow():
    return service_request('user/register-now')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    print "Starting with client_id", app.config['CLIENT_ID']
    app.run(host='0.0.0.0', port=8000, threaded=True)
