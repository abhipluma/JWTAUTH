# flask imports
import uuid  # for public id
from datetime import datetime, timedelta
from functools import wraps

# imports for PyJWT authentication
import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from flask_restful import Resource, Api
from apispec import APISpec
from marshmallow import Schema, fields
from apispec.ext.marshmallow import MarshmallowPlugin
from flask_apispec.extension import FlaskApiSpec
from flask_apispec.views import MethodResource
from flask_apispec import marshal_with, doc, use_kwargs

# creates Flask object
app = Flask(__name__)  # Flask app instance initiated
api = Api(app)  # Flask restful wraps Flask app around it.
app.config.update({
    'APISPEC_SPEC': APISpec(
        title='Enterprize App',
        version='v1',
        plugins=[MarshmallowPlugin()],
        openapi_version='2.0.0'
    ),
    'APISPEC_SWAGGER_URL': '/swagger/',  # URI to access API Doc JSON
    'APISPEC_SWAGGER_UI_URL': '/swagger-ui/'  # URI to access UI of API Doc
})
docs = FlaskApiSpec(app)
# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
app.config['SECRET_KEY'] = 'your secret key'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)

class UserSchema(Schema):
    name = fields.Str()
    email = fields.Str()
    class Meta:
        fields = ('email','name')

class LoginSchema(Schema):
    password = fields.Str()
    email = fields.Str()
    class Meta:
        fields = ('email','password')

class SignupSchema(Schema):
    password = fields.Str()
    email = fields.Str()
    class Meta:
        fields = ('email','password')

user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query \
                .filter_by(public_id=data['public_id']) \
                .first()
        except Exception as e:
            print(e)
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated


# User Database Route
# this route sends back list of users users
class UserAPI(MethodResource, Resource):
    @token_required
    @doc(description='User List', tags=['User List'])
    @marshal_with(UserSchema)
    def get(self, current_user):
        # querying the database
        # for all the entries in it
        users = User.query.all()
        marshmallow_serial_data = users_schema.dump(users)
        return jsonify({'users': marshmallow_serial_data})


# route for loging user in
class LoginAPI(MethodResource, Resource):
    @doc(description='Log In', tags=['Log In'])
    def post(self):
        # creates dictionary of form data
        auth = request.form

        if not auth or not auth.get('email') or not auth.get('password'):
            # returns 401 if any email or / and password is missing
            return make_response(
                'Could not verify',
                401,
                {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
            )

        user = User.query \
            .filter_by(email=auth.get('email')) \
            .first()

        if not user:
            # returns 401 if user does not exist
            return make_response(
                'Could not verify',
                401,
                {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
            )

        if check_password_hash(user.password, auth.get('password')):
            # generates the JWT Token
            token = jwt.encode({
                'public_id': user.public_id,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, app.config['SECRET_KEY'])
            return make_response(jsonify({'token': str(token)}), 201)
        # returns 403 if password is wrong
        return make_response(
            'Could not verify',
            403,
            {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
        )


# signup route
class SignupAPI(MethodResource, Resource):
    @doc(description='Sign up', tags=['Sign up'])
    def post(self):
        # creates a dictionary of the form data
        data = request.form

        # gets name, email and password
        name, email = data.get('name'), data.get('email')
        password = data.get('password')

        # checking for existing user
        user = User.query \
            .filter_by(email=email) \
            .first()
        if not user:
            # database ORM object
            user = User(
                public_id=str(uuid.uuid4()),
                name=name,
                email=email,
                password=generate_password_hash(password)
            )
            # insert user
            db.session.add(user)
            db.session.commit()

            return make_response('Successfully registered.', 201)
        else:
            # returns 202 if user already exists
            return make_response('User already exists. Please Log in.', 202)


api.add_resource(UserAPI, '/user')
api.add_resource(LoginAPI, '/login')
api.add_resource(SignupAPI, '/signup')
docs.register(UserAPI)
docs.register(SignupAPI)
docs.register(LoginAPI)


if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debuger shell
    # if you hit an error while running the server
    app.run(debug=True)
