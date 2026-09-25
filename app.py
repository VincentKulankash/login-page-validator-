from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, reqparse, Resource, marshal_with, fields, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite///users.db'
db = SQLAlchemy(app)
api = Api(app)


class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(80), unique = True, nullable= False)
    email = db.Column(db.String(120), unique = True, nullable= False)
    password_hash = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"User(username={self.username}, email={self.email})"

signup_args = reqparse.RequestParser()
signup_args.add_argument('username', type=str, required=True, help='Username cannot be blank')
signup_args.add_argument('email', type=str, required=True, help='Email cannot be blank')
signup_args.add_argument('password', type=str, required=True, help='Password cannot be blank')

login_args = reqparse.RequestParser()
login_args.add_argument('username', type=str, required=True, help='Username cannot be blank')
login_args.add_argument('password', type=str, required=True, help='Password cannot be blank')


#Out-put shape password cannot leave the server
user_fields = {
    'id': fields.Integer,
    'username': fields.String,
    'email': fields.String,
}

#Resources 
class Signup (Resource):
    @marshal_with(user_fields)
    def post (self):
        args = signup_args.parse_args()

        if len(args['password']) < 6:
            abort (400, message= 'Invalid email address')

        if UserModel.query.filter_by(username=args['username']).first():
            abort (409, message='Username already taken')
        if UserModel.query.filter_by(email=args['email']).first():
            abort (409, message='Email already exists')

        user = UserModel(
            username=args['username'],
            email=args['email'],
            password_hash=generate_password_hash(args['password']),
        )

        db.session.add(user)
        db.session.commit()
        return user, 201

class Login(Resource):
    def post (self):
        args = login_args.parse_args()

        user = UserModel.query.filter_by(username=args['username']).first()
        if not user or not check_password_hash(user.password_hash, args['password']):
            abort (401, message= 'Invalid username or password')

        return {
            'message': 'login successful',
            'user_id': user.id,
            'username': user.username,
        }, 200

class UserProfile (Resource):
    @marshal_with(user_fields)
    def get (self, user_id):
        user = UserModel.query.get(user_id)
        if not user:
            abort (404, message=f'User {user_id} not found')
        return user

api.add_resource(Signup, '/api/signup')
api.add_resource(Login, '/api/login')
api.add_resource(UserProfile, '/api/users/<user_id>')

@app.route('/')
def home ():
    return render_template('index.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)