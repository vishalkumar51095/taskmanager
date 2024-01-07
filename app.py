import uuid
from functools import wraps
from datetime import datetime, timedelta
import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

import logging

# Set up logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')


app = Flask(__name__)

app.config['SECRET_KEY'] = '70efba9dd09069540fb7ee09'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:vishal@localhost:5432/task-manager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(255))
    admin = db.Column(db.Boolean)

    # Define the relationship back to Task model
    tasks = relationship('Task', back_populates='user')


class Task(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    # Define the foreign key referencing User's public_id
    user_id = db.Column(db.Integer, ForeignKey('user.id'))

    # Define the relationship
    user = relationship('User', back_populates='tasks')

    def __repr__(self) -> str:
        return f"{self.sno} - {self.title}"


# Create tables
with app.app_context():
    db.create_all()


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
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                # Proceed with the rest of your code
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired!'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token!'}), 401
            except Exception as e:
                return jsonify({'message': 'Error decoding token: ' + str(e)}), 500
            print(data)
            current_user = User.query \
                .filter_by(public_id=data['public_id']) \
                .first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged-in users context to the routes
        return f(current_user, *args, **kwargs)

    return decorated


# User Database Route
# this route sends back list of users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'email': user.email,
                 'admin': user.admin}

    return jsonify({'user': user_data})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


# route for logging user in
@app.route('/login', methods=['POST'])
def login():
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

        return make_response(jsonify({'token': token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


# signup route
@app.route('/signup', methods=['POST'])
def signup():
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


# Create a new task
@app.route('/tasks', methods=['POST'])
@token_required
def create_task(current_user):
    data = request.get_json()
    new_task = Task(title=data['title'], desc=data['desc'], user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'New task created!'}), 201


@app.route('/task/<int:sno>', methods=['PUT'])
@token_required
def update_task(current_user, sno):
    task = Task.query.filter_by(sno=sno, user_id=current_user.id).first()

    if not task:
        return jsonify({'message': 'Task not found!'})

    data = request.get_json()

    if 'title' in data:
        task.title = data['title']
    if 'desc' in data:
        task.desc = data['desc']

    db.session.commit()

    return jsonify({'message': 'Task updated!'})
# Delete a task by sno
@app.route('/task/<int:sno>', methods=['DELETE'])
@token_required
def delete_task(sno, current_user):
    task = Task.query.filter_by(id=sno, user_id=current_user.id)
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted!'})


@app.route('/tasks', methods=['GET'])
@token_required
def get_all_tasks(current_user):
    tasks = Task.query.filter_by(user_id=int(current_user.id)).all()

    output = []

    for task in tasks:
        task_data = {
            'id': task.sno,
            'title': task.title,
            'description': task.desc,
            'create_date': task.date_created,
            'user_id': current_user.id
        }
        output.append(task_data)

    return jsonify({'tasks': output})


@app.route('/task/<int:sno>', methods=['GET'])
@token_required
def get_tasks_by_sno(current_user, sno):
    tasks = Task.query.filter_by(sno=sno, user_id=current_user.id)

    output = []

    for task in tasks:
        task_data = {'sno': task.sno, 'title': task.title, 'description': task.desc, 'create_date': task.date_created}
        output.append(task_data)

    return jsonify({'tasks': output})


if __name__ == '__main__':
    app.run(debug=True)
