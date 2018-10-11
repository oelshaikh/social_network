#!flask/bin/python
from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256 as sha256
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:kharboot@localhost/social_net'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'my-super-secret-string'

app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = True

db = SQLAlchemy(app)
jwt = JWTManager(app)


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(120), nullable = False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username = username).first()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)


@app.route('/', methods=['get'])
def home():
    return "You are home"


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', None)
    password = request.form.get('password', None)
    current_user = UserModel.find_by_username(username)
    if not current_user:
        return jsonify({'message': 'User {} doesn\'t exist'.format(username)})

    if UserModel.verify_hash(password, current_user.password):
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        resp = jsonify({'login': True})
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        return resp, 200
    else:
        return jsonify({'message': 'Wrong credentials'})

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', None)
    password = request.form.get('password', None)
    if UserModel.find_by_username(username):
            return jsonify({'message': 'User {} already exists'. format(username)})
    new_user = UserModel(
        username = username,
        password = UserModel.generate_hash(password)
    )        
    try:
        new_user.save_to_db()
        return jsonify({'message': 'User {} was created'.format(username)})
    except:
        return jsonify({'message': 'Something went wrong'}), 500

@app.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    # Create the new access token
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)

    # Set the access JWT and CSRF double submit protection cookies
    # in this response
    resp = jsonify({'refresh': True})
    set_access_cookies(resp, access_token)
    return resp, 200

@app.route('/token/remove', methods=['POST'])
def logout():
    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    return resp, 200


@app.route('/api/example', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200

if __name__ == '__main__':
    app.run(debug=True)