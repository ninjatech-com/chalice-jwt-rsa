from chalice import Chalice, AuthResponse
import passlib

import authtools

app = Chalice(app_name='authapp')


@app.route('/')
def index():
    return {'hello': 'world'}


@app.route('/login', methods=['OPTIONS', 'POST'])
def login():
    body = app.current_request.json_body
    # record = get_users_db().get_item(
    #     Key={'username': body['username']})['Item']
    jw_token = authtools.sign(claims={'sub': "foo bar", 'aud': authtools.AUDIENCE})
    # jwt_token = auth.get_jwt_token(
    #     body['username'], body['password'], record)
    return {'token': jw_token}


@app.authorizer()
def jwt_auth(auth_request):
    token = auth_request.token.split(' ')[1]
    decoded = authtools.validate(token)
    return AuthResponse(routes=['*'], principal_id=decoded['sub'])


@app.route('/credentials/validate', methods=['POST'], authorizer=jwt_auth)
def validate_creds():
    ...


@app.route('/credentials/store', methods=['POST'], authorizer=jwt_auth)
def store_creds():
    ...


@app.route('/credentials', authorizer=jwt_auth)
def list_creds():
    ...


@app.route('/credentials/jwks')
def serve_jwks():
    ...


@app.route('/secured', methods=["GET"], authorizer=jwt_auth)
def test_secure():
    return {'secured': 'sample data'}

# The view function above will return {"hello": "world"}
# whenever you make an HTTP GET request to '/'.
#
# Here are a few more examples:
#
# @app.route('/hello/{name}')
# def hello_name(name):
#    # '/hello/james' -> {"hello": "james"}
#    return {'hello': name}
#
# @app.route('/users', methods=['POST'])
# def create_user():
#     # This is the JSON body the user sent in their POST request.
#     user_as_json = app.current_request.json_body
#     # We'll echo the json body back to the user in a 'user' key.
#     return {'user': user_as_json}
#
# See the README documentation for more examples.
#
