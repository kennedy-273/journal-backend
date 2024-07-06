from flask import Flask, request, make_response, jsonify
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import timedelta
from dotenv import load_dotenv
import os
import cloudinary
import cloudinary.uploader

from models import db, User, Journal

app = Flask(__name__)
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES_DAYS')))
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES_DAYS')))

cloudinary.config( 
    cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'), 
    api_key = os.getenv('CLOUDINARY_API_KEY'), 
    api_secret = os.getenv('CLOUDINARY_API_SECRET'), 
    secure=True
)

migrate = Migrate(app, db)
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
api = Api(app)
CORS(app, resources={r"/*": {"origins": "*"}})

# RESTful routes
# Sign in
class SignIn(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400

        email = data.get('email')
        password = data.get('password')
       
        user = User.query.filter_by(email=email).first()
       
        if not user:
            return {"error": "User does not exist"}, 401
        if not bcrypt.check_password_hash(user.password, password):
            return {"error": "Incorrect password"}, 401
       
        access_token = create_access_token(identity={'id': user.id})
        refresh_token = create_refresh_token(identity={'id': user.id})
        return {"access_token": access_token, "refresh_token": refresh_token}, 200

api.add_resource(SignIn, '/signin')

# Sign up
class SignUp(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400
        
        # validate data
        try:
            user = User(
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                password=data['password']
            )
        except AssertionError as error:
            return {"error": str(error)}, 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            password=hashed_password
            )
       
        db.session.add(user)
        db.session.commit()
       
        access_token = create_access_token(identity={'id': user.id})
        refresh_token = create_refresh_token(identity={'id': user.id})
        return make_response({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict()
        }, 201)

api.add_resource(SignUp, '/signup')

# Refresh Token
class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        try:
            current_user = get_jwt_identity()
            access_token = create_access_token(identity=current_user)
            return {'access_token': access_token}, 200
        except Exception as e:
            return jsonify(error=str(e)), 500

api.add_resource(TokenRefresh, '/refresh-token')

# Users (get post)
class Users(Resource):
    @jwt_required()
    def get(self):        
        users = [user.to_dict() for user in User.query.all()]
        return make_response(users,200)
     
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400
   
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            password=hashed_password
            )
       
        db.session.add(user)
        db.session.commit()
        return make_response(user.to_dict(), 201)
   
api.add_resource(Users, '/users')

# User By ID (get patch delete)
class UserByID(Resource):
    @jwt_required()
    def get(self, id):
        user = User.query.filter_by(id=id).first()
        if user is None:
            return {"error": "User not found"}, 404
        response_dict = user.to_dict()
        return make_response(response_dict, 200)
   
    @jwt_required()
    def patch(self, id):
        user = User.query.filter_by(id=id).first()
        if user is None:
            return {"error": "User not found"}, 404

        if 'first_name' in request.form:
            user.first_name = request.form['first_name']
        if 'last_name' in request.form:
            user.last_name = request.form['last_name']
        if 'email' in request.form:
            user.email = request.form['email']
        if 'password' in request.form:
            user.password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if 'image' in request.files:
            image = request.files['image']
            user.upload_image(image)

        try:
            db.session.commit()
            return make_response(user.to_dict(), 200)
        except AssertionError:
            return {"errors": ["validation errors"]}, 400

    @jwt_required()
    def delete(self, id):             
        user = User.query.filter_by(id=id).first()
        if user is None:
            return {"error": "User not found"}, 404
       
        user = User.query.get_or_404(id)
        db.session.delete(user)
        db.session.commit()
        return make_response({'message': 'User deleted successfully'})
   
api.add_resource(UserByID, '/user/<int:id>')

# Journals (get post)
class Journals(Resource):
    @jwt_required()
    def get(self):
        journals = [journal.to_dict() for journal in Journal.query.all()]
        return make_response(journals, 200)
   
    @jwt_required()
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400
       
        user_id = get_jwt_identity()
    
        journal = Journal(
            title=data['title'],
            body=data['body'],
            category=data['category'],
            user_id=user_id
        )
       
        db.session.add(journal)
        db.session.commit()
        return make_response(journal.to_dict(), 201)

api.add_resource(Journals, '/journals')


# Journal By ID (get patch delete)
class JournalByID(Resource):
    @jwt_required()
    def get(self, id):
        journal = Journal.query.filter_by(id=id).first()
        if journal is None:
            return {"error": "Journal not found"}, 404
        response_dict = journal.to_dict()
        return make_response(response_dict, 200)
   
    @jwt_required()
    def patch(self, id):
        journal = Journal.query.filter_by(id=id).first()
        if journal is None:
            return {"error": "Journal not found"}, 404

        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400

        if 'title' in data:
            journal.title = data['title']
        if 'body' in data:
            journal.body = data['body']
        if 'category' in data:
            journal.category = data['category']
        if 'created_at' in data:
            journal.created_at = data['created_at']

        try:
            db.session.commit()
            return make_response(journal.to_dict(), 200)
        except AssertionError:
            return {"errors": ["validation errors"]}, 400

    @jwt_required()
    def delete(self, id):             
        journal = Journal.query.filter_by(id=id).first()
        if journal is None:
            return {"error": "Journal not found"}, 404
        
       
        journal = Journal.query.get_or_404(id)
        db.session.delete(journal)
        db.session.commit()
        return make_response({'message': 'Journal deleted successfully'})
   
api.add_resource(JournalByID, '/journal/<int:id>')

if __name__ == '__main__':
    app.run(debug=True, port=5500)

