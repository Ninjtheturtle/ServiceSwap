from flask import Flask, render_template, redirect, url_for, request, jsonify, session
import requests
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.types import JSON
from math import radians, cos, sin, asin, sqrt
from search_utils import filter_by_semantic_similarity

# App setup
app = Flask(__name__)
app.config["SECRET_KEY"] = "SomeSecret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join("static", "imgs", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='eventlet')

# Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Models
class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    talking_to = db.Column(MutableList.as_mutable(JSON), default=list)

    bio = db.Column(db.Text, default="")
    qualifications = db.Column(MutableList.as_mutable(JSON), default=list)
    profile_picture = db.Column(db.String(200), default="imgs/user.png")

# Message model for persistent messaging
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('Users', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('Users', foreign_keys=[receiver_id], backref='received_messages')

# Listing
class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(120))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    user = db.relationship('Users', backref='listings')

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rater_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ratee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    rater = db.relationship('Users', foreign_keys=[rater_id], backref='given_ratings')
    ratee = db.relationship('Users', foreign_keys=[ratee_id], backref='received_ratings')
    
# Forms
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    email = StringField("Email", validators=[InputRequired(), Length(min=5, max=50), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")

    

@app.before_request
def create_tables():
    app.before_request_funcs[None].remove(create_tables)
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Haversine distance calculator
def haversine(lon1, lat1, lon2, lat2):
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    r = 6371
    return c * r

# Routes
@app.route("/")
@login_required
def index():
    distance_filter = request.args.get("distance", "any")
    search_query = request.args.get("q", "").strip().lower()

    listings_query = Listing.query.options(db.joinedload(Listing.user)).filter(Listing.user_id != current_user.id)

    user_lat = session.get("lat")
    user_lon = session.get("lon")

    # Step 1: Filter by distance (if any)
    if distance_filter != "any" and user_lat and user_lon:
        try:
            max_distance = float(distance_filter)
            filtered = []
            for listing in listings_query.all():
                if listing.latitude and listing.longitude:
                    d = haversine(float(user_lon), float(user_lat), listing.longitude, listing.latitude)
                    if d <= max_distance:
                        filtered.append(listing)
            listings = filtered
        except Exception as e:
            print("Distance filtering failed:", e)
            listings = listings_query.all()
    else:
        listings = listings_query.all()

    # Step 2: Filter semantically if a query is present
    if search_query:
        listings = filter_by_semantic_similarity(search_query, listings)

    # Step 3: Convert to dictionary format for rendering
    listings_data = [
        {
            "id": listing.id,
            "description": listing.description,
            "image_path": listing.image_path,
            "latitude": listing.latitude,
            "longitude": listing.longitude,
            "user": {
                "id": listing.user.id,
                "username": listing.user.username,
                "bio": listing.user.bio,
                "qualifications": listing.user.qualifications,
                "profile_picture": listing.user.profile_picture or "imgs/user.png",
                "avg_rating": calculate_avg_rating(listing.user)
            }

        }
        for listing in listings
    ]

    return render_template(
        "index.html",
        listings=listings,
        listings_data=listings_data,
        distance_filter=distance_filter
    )

@app.route("/api/search", methods=["POST"])
@login_required
def api_search():
    data = request.get_json()
    search_query = data.get("q", "").strip().lower()
    distance_filter = data.get("distance", "any")

    listings_query = Listing.query.options(db.joinedload(Listing.user)).filter(Listing.user_id != current_user.id)

    user_lat = session.get("lat")
    user_lon = session.get("lon")

    if distance_filter != "any" and user_lat and user_lon:
        try:
            max_distance = float(distance_filter)
            listings_query = [
                listing for listing in listings_query.all()
                if listing.latitude and listing.longitude and
                haversine(float(user_lon), float(user_lat), listing.longitude, listing.latitude) <= max_distance
            ]
        except:
            listings_query = listings_query.all()
    else:
        listings_query = listings_query.all()

    if search_query:
        listings_query = filter_by_semantic_similarity(search_query, listings_query)

    listings_data = [
        {
            "id": l.id,
            "description": l.description,
            "image_path": l.image_path,
            "user": {
                "id": l.user.id,
                "username": l.user.username,
                "bio": l.user.bio,
                "qualifications": l.user.qualifications,
                "profile_picture": l.user.profile_picture or "imgs/user.png",
                "avg_rating": calculate_avg_rating(l.user)
            }
        } for l in listings_query
    ]

    return jsonify(listings_data)

@app.route("/set-location", methods=["POST"])
def set_location():
    data = request.get_json()
    session["lat"] = data.get("latitude")
    session["lon"] = data.get("longitude")
    return jsonify({"status": "ok"})

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = Users.query.filter_by(email=form.email.data).first()
        if existing_user:
            return render_template("signup.html", form=form, error="Email already in use.")
        existing_username = Users.query.filter_by(username=form.username.data).first()
        if existing_username:
            return render_template("signup.html", form=form, error="Username already taken.")
        hashed_pw = generate_password_hash(form.password.data)
        new_user = Users(username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        logout_user()
        return redirect(url_for("login"))
    return render_template("signup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember)
            return redirect(url_for("index"))
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/listings")
@login_required
def listings():
    user_listings = Listing.query.filter_by(user_id=current_user.id).options(db.joinedload(Listing.user)).all()
    return render_template("listings.html", listings=user_listings)

@app.route("/add-listing", methods=["POST"])
@login_required
def add_listing():
    description = request.form.get("description")
    image = request.files.get("image")

    image_filename = None
    if image and image.filename != "":
        filename = secure_filename(image.filename)
        import time
        filename = f"{int(time.time())}_{filename}"
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        image.save(image_path)
        image_filename = f"imgs/uploads/{filename}"

    lat = session.get("lat")
    lon = session.get("lon")

    new_listing = Listing(
        description=description,
        image_path=image_filename,
        user_id=current_user.id,
        latitude=lat,
        longitude=lon
    )
    db.session.add(new_listing)
    db.session.commit()

    return redirect(url_for("listings"))

@app.route('/edit-listing/<int:listing_id>', methods=['POST'])
@login_required
def edit_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if listing.user_id != current_user.id:
        return "Unauthorized", 403
    listing.description = request.form['description']
    db.session.commit()
    return redirect(url_for('listings'))

@app.route('/delete-listing/<int:listing_id>', methods=['POST'])
@login_required
def delete_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    if listing.user_id != current_user.id:
        return "Unauthorized", 403
    db.session.delete(listing)
    db.session.commit()
    return redirect(url_for('listings'))

@app.route('/inbox/')
@login_required
def inbox():
    talking_to_ids = current_user.talking_to
    
    # Get chat users with last message and unread count
    chat_users = []
    for user_id in talking_to_ids:
        user = Users.query.get(user_id)
        if user:
            # Get last message between current user and this user
            last_message = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
                ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
            ).order_by(Message.timestamp.desc()).first()
            
            # Count unread messages from this user
            unread_count = Message.query.filter(
                Message.sender_id == user_id,
                Message.receiver_id == current_user.id,
                Message.is_read == False
            ).count()
            
            chat_users.append({
                'user': user,
                'last_message': last_message,
                'unread_count': unread_count
            })
    
    # Sort by last message timestamp (most recent first)
    chat_users.sort(key=lambda x: x['last_message'].timestamp if x['last_message'] else datetime.min, reverse=True)
    
    chat_with_id = request.args.get("chat_with", type=int)

    # Convert user objects to lightweight dicts for JS
    chat_users_data = [
        {
            "id": chat['user'].id, 
            "username": chat['user'].username,
            "unread_count": chat['unread_count']
        }
        for chat in chat_users
    ]

    return render_template("inbox.html", chat_users=chat_users, current_user=current_user,
                           chat_with_id=chat_with_id, chat_users_json=chat_users_data)

@app.route('/get-messages/<int:user_id>')
@login_required
def get_messages(user_id):
    """Get all messages between current user and specified user"""
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Mark messages as read
    Message.query.filter(
        Message.sender_id == user_id,
        Message.receiver_id == current_user.id,
        Message.is_read == False
    ).update({'is_read': True})
    db.session.commit()
    
    messages_data = [
        {
            'id': msg.id,
            'sender_id': msg.sender_id,
            'sender_username': msg.sender.username,
            'content': msg.content,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_read': msg.is_read
        }
        for msg in messages
    ]
    
    return jsonify(messages_data)

@app.route('/send-message', methods=['POST'])
@login_required
def send_message():
    """Send a message to another user"""
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    
    if not receiver_id or not content:
        return jsonify({'error': 'Missing receiver_id or content'}), 400
    
    # Verify receiver exists
    receiver = Users.query.get(receiver_id)
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    
    # Create and save message
    message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content.strip()
    )
    db.session.add(message)
    db.session.commit()
    
    # Emit message via Socket.IO for real-time updates
    room = '_'.join(sorted([current_user.username, receiver.username]))
    socketio.emit('private_message', {
        'id': message.id,
        'sender_id': message.sender_id,
        'receiver_id': message.receiver_id,
        'sender_username': current_user.username,
        'content': message.content,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'is_read': message.is_read
    }, room=room)
    
    return jsonify({
        'id': message.id,
        'sender_id': message.sender_id,
        'receiver_id': message.receiver_id,
        'sender_username': current_user.username,
        'content': message.content,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'is_read': message.is_read
    })


@app.route('/add-contact', methods=['POST'])
@login_required
def add_contact():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id or not isinstance(user_id, int):
        return jsonify({"error": "Invalid user ID"}), 400
    if user_id == current_user.id:
        return jsonify({"error": "Cannot add yourself"}), 400

    # Find the other user
    other_user = Users.query.get(user_id)
    if not other_user:
        return jsonify({"error": "User not found"}), 404

    # Add other user to current user's list
    if current_user.talking_to is None:
        current_user.talking_to = []
    if user_id not in current_user.talking_to:
        current_user.talking_to.append(user_id)

    # Add current user to other user's list
    if other_user.talking_to is None:
        other_user.talking_to = []
    if current_user.id not in other_user.talking_to:
        other_user.talking_to.append(current_user.id)

    # Commit changes
    db.session.add(current_user)
    db.session.add(other_user)
    db.session.commit()

    return jsonify({"message": "Users are now mutually added to talking_to lists."})

@socketio.on('join_room')
def handle_join(data):
    join_room(data['room'])

@socketio.on('private_message')
def handle_pm(data):
    """Handle real-time message sending via Socket.IO - REMOVED TO AVOID DUPLICATES"""
    # This function is no longer needed since we handle message sending via REST API
    # and emit via Socket.IO in the send_message route
    pass

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        bio = request.form.get("bio")
        qualifications = request.form.getlist("qualification")
        profile_file = request.files.get("profile")

        current_user.username = username
        current_user.email = email
        current_user.bio = bio
        current_user.qualifications = qualifications

        if profile_file and profile_file.filename != "":
            filename = secure_filename(profile_file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            profile_file.save(filepath)
            current_user.profile_picture = f"imgs/uploads/{filename}"

        db.session.commit()
        return redirect(url_for("profile"))

    avg_rating = calculate_avg_rating(current_user)
    return render_template("profile.html", user=current_user, avg_rating=avg_rating)

def calculate_avg_rating(user):
    ratings = Rating.query.filter_by(ratee_id=user.id).all()
    if not ratings:
        return None
    return round(sum(r.score for r in ratings) / len(ratings), 2)

@app.route("/rate-user", methods=["POST"])
@login_required
def rate_user():
    data = request.get_json()
    ratee_id = data.get("user_id")
    score = data.get("score")

    if not isinstance(score, int) or not (1 <= score <= 5):
        return jsonify({"error": "Invalid score"}), 400

    if ratee_id == current_user.id:
        return jsonify({"error": "You can't rate yourself!"}), 400

    # Optional: check if the user has chatted before rating
    if ratee_id not in current_user.talking_to:
        return jsonify({"error": "You can only rate people you've chatted with."}), 403

    rating = Rating(rater_id=current_user.id, ratee_id=ratee_id, score=score)
    db.session.add(rating)
    db.session.commit()

    return jsonify({"message": "Rating submitted!"})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, port=5001)