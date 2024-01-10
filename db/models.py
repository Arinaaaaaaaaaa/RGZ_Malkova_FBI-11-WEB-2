from . import db
from werkzeug.security import generate_password_hash, check_password_hash

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(256))
    name = db.Column(db.String(50))
    avatar = db.Column(db.String(1000))
    contact = db.Column(db.String(256))
    about = db.Column(db.String(120))

    def __repr__(self):
        return f'id:{self.id}, username:{self.username}'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def is_active(self):
        return True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True
    

class Advertisements(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(400))
    main_text = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    author_name = db.Column(db.Text)
    email = db.Column(db.String(100))
    photo = db.Column(db.Text)

    def __repr__(self):
        return f'id:{self.id}, subject:{self.subject}'