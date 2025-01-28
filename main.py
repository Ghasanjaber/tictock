import os
import uuid
import jwt
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt
from werkzeug.utils import secure_filename

###################################################
# Configuration & Initialization33
###################################################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'REPLACE_WITH_YOUR_OWN_SECRET'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tiktok_clone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Folder where uploaded videos will be stored (local demo)
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

###################################################
# Database Models
###################################################
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Video(db.Model):
    __tablename__ = 'videos'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    video_path = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    moderation_status = db.Column(db.String(20), default='pending')  # "pending", "approved", "flagged"

    # Relationship fields
    likes = db.relationship('User', secondary='video_likes', backref='liked_videos')
    comments = db.relationship('Comment', backref='video', lazy='dynamic')


# Association table for many-to-many "likes"
video_likes = db.Table('video_likes',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('video_id', db.Integer, db.ForeignKey('videos.id'), primary_key=True)
)

###################################################
# Database Setup
###################################################
@app.before_first_request
def create_tables():
    db.create_all()

###################################################
# Utility Functions
###################################################
def create_jwt_token(user_id):
    """
    Create a JWT token that expires in 7 days.
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def decode_jwt_token(token):
    """
    Decode a JWT token and return the payload (which includes user_id).
    Raises an exception if token is invalid or expired.
    """
    return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

def token_required(f):
    """
    Decorator that requires a valid JWT token in the Authorization header.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', None)
        if not auth_header:
            return jsonify({'message': 'Missing authorization header'}), 401

        try:
            # Expected format: "Bearer <token>"
            token = auth_header.split(" ")[1]
            decoded = decode_jwt_token(token)
            user_id = decoded['user_id']
            user = User.query.get(user_id)
            if not user:
                return jsonify({'message': 'Invalid token user'}), 401
            # Attach user to request context
            request.current_user = user
        except Exception as e:
            return jsonify({'message': f'Invalid or expired token: {str(e)}'}), 401

        return f(*args, **kwargs)
    return decorated

###################################################
# Auth Routes
###################################################
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing JSON body'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    # Check if user exists
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return jsonify({'message': 'Username or email already taken'}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 200

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Missing JSON body'}), 400

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid email or password'}), 401

    token = create_jwt_token(user.id)
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'userId': user.id,
        'username': user.username
    }), 200

###################################################
# Video Routes
###################################################
@app.route('/api/videos/upload', methods=['POST'])
@token_required
def upload_video():
    """
    Upload a video file to the server.
    """
    # Title, description
    title = request.form.get('title', '')
    description = request.form.get('description', '')

    if 'video' not in request.files:
        return jsonify({'message': 'No video file provided'}), 400

    file = request.files['video']
    if file.filename == '':
        return jsonify({'message': 'Empty file name'}), 400

    # Sanitize file name and store it
    filename = secure_filename(file.filename)
    # Example: create a random name to avoid collisions
    unique_name = str(uuid.uuid4()) + "_" + filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    file.save(file_path)

    # Create a new video record
    new_video = Video(
        user_id=request.current_user.id,
        title=title,
        description=description,
        video_path=unique_name,  # store only the filename
        moderation_status='pending'
    )
    db.session.add(new_video)
    db.session.commit()

    return jsonify({
        'message': 'Video uploaded successfully',
        'video': {
            'id': new_video.id,
            'title': new_video.title,
            'description': new_video.description
        }
    }), 200

@app.route('/api/videos/feed', methods=['GET'])
def get_feed():
    """
    Returns a list of approved videos in descending order by creation time.
    """
    videos = Video.query.filter_by(moderation_status='approved').order_by(Video.created_at.desc()).all()
    feed = []
    for v in videos:
        feed.append({
            'id': v.id,
            'title': v.title,
            'description': v.description,
            'videoUrl': f'/api/videos/play/{v.video_path}',
            'likesCount': len(v.likes),
            'comments': [
                {
                    'id': c.id,
                    'text': c.text,
                    'user_id': c.user_id
                } for c in v.comments.order_by(Comment.created_at.asc())
            ],
            'userId': v.user_id,
            'createdAt': v.created_at
        })
    return jsonify(feed), 200

@app.route('/api/videos/play/<path:filename>', methods=['GET'])
def play_video(filename):
    """
    Serve the video file from the uploads folder.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/videos/<int:video_id>/like', methods=['POST'])
@token_required
def like_video(video_id):
    """
    Toggle like on a video for the current user.
    """
    video = Video.query.get(video_id)
    if not video:
        return jsonify({'message': 'Video not found'}), 404

    user = request.current_user
    if user in video.likes:
        # Already liked, remove like
        video.likes.remove(user)
        db.session.commit()
        return jsonify({'message': 'Like removed', 'likesCount': len(video.likes)})
    else:
        # Add like
        video.likes.append(user)
        db.session.commit()
        return jsonify({'message': 'Video liked', 'likesCount': len(video.likes)})

@app.route('/api/videos/<int:video_id>/comment', methods=['POST'])
@token_required
def comment_video(video_id):
    """
    Add a comment to a video.
    """
    video = Video.query.get(video_id)
    if not video:
        return jsonify({'message': 'Video not found'}), 404

    data = request.get_json()
    text = data.get('text', '')

    if not text:
        return jsonify({'message': 'Comment text required'}), 400

    new_comment = Comment(text=text, user_id=request.current_user.id)
    video.comments.append(new_comment)
    db.session.commit()
    return jsonify({'message': 'Comment added'}), 200

###################################################
# Recommendation Routes
###################################################
@app.route('/api/recommend', methods=['GET'])
@token_required
def get_recommendations():
    """
    Very naive approach: just return random or most recent videos.
    You can replace this with your real recommendation logic.
    """
    videos = Video.query.filter_by(moderation_status='approved').all()
    # Return up to 5 "recommended" in reverse creation order (or random).
    # For a real system, you'd implement collaborative filtering, etc.
    videos_sorted = sorted(videos, key=lambda v: v.created_at, reverse=True)
    recommended = videos_sorted[:5]

    results = []
    for v in recommended:
        results.append({
            'id': v.id,
            'title': v.title,
            'description': v.description,
            'videoUrl': f'/api/videos/play/{v.video_path}',
            'likesCount': len(v.likes),
            'createdAt': v.created_at
        })
    return jsonify(results), 200

###################################################
# Moderation Routes
###################################################
@app.route('/api/moderation/<int:video_id>', methods=['POST'])
def moderate_video(video_id):
    """
    Dummy moderation endpoint (no auth check for simplicity).
    Expect a JSON body: { "action": "approve" or "flag" }
    In a real system, you'd restrict this to admin roles only.
    """
    video = Video.query.get(video_id)
    if not video:
        return jsonify({'message': 'Video not found'}), 404

    data = request.get_json()
    action = data.get('action')
    if action not in ['approve', 'flag']:
        return jsonify({'message': 'Invalid action'}), 400

    if action == 'approve':
        video.moderation_status = 'approved'
    elif action == 'flag':
        video.moderation_status = 'flagged'

    db.session.commit()
    return jsonify({'message': f'Video {action}d successfully', 'video_id': video_id}), 200

###################################################
# Run the App
###################################################
if __name__ == '__main__':
    app.run(debug=True, port=5000)
