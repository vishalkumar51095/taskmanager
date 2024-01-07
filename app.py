from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask(__name__)

app.config['SECRET_KEY']='70efba9dd09069540fb7ee09'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:vishal@localhost:5432/task-manager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))


class Task(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"{self.sno} - {self.title}"


# Create tables
with app.app_context():
    db.create_all()


# Create a new user
@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'}), 201


@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:
        user_data = {'id': user.id, 'username': user.username, 'password': user.password}
        output.append(user_data)
    return jsonify({'users': output})


@app.route('/user/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
    user = User.query.get(user_id)
    if user:
        user_data = {
            'id': user.id,
            'username': user.username,
            'password': user.password
        }
        return jsonify({'user': user_data}), 200
    return jsonify({'message': 'User not found'}), 404


# Get all tasks
@app.route('/tasks', methods=['GET'])
def get_all_tasks():
    tasks = Task.query.all()
    output = []
    for task in tasks:
        task_data = {'sno': task.sno, 'title': task.title, 'desc': task.desc, 'date_created': task.date_created}
        output.append(task_data)
    return jsonify({'tasks': output})


# Get one task by sno
@app.route('/tasks/<int:sno>', methods=['GET'])
def get_one_task(sno):
    task = Task.query.get_or_404(sno)
    task_data = {'sno': task.sno, 'title': task.title, 'desc': task.desc, 'date_created': task.date_created}
    return jsonify({'task': task_data})


# Create a new task
@app.route('/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    new_task = Task(title=data['title'], desc=data['desc'])
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'New task created!'}), 201


# Update a task by sno
@app.route('/tasks/<int:sno>', methods=['PUT'])
def update_task(sno):
    task = Task.query.get_or_404(sno)
    data = request.get_json()
    task.title = data['title']
    task.desc = data['desc']
    db.session.commit()
    return jsonify({'message': 'Task updated!'})


# Delete a task by sno
@app.route('/tasks/<int:sno>', methods=['DELETE'])
def delete_task(sno):
    task = Task.query.get_or_404(sno)
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted!'})


if __name__ == '__main__':
    app.run(debug=True)
