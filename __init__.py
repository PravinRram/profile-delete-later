import base64
import json
import os
import secrets
import uuid
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import urlopen

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from markupsafe import Markup
from sqlalchemy import or_
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
from models import Follow, Hobby, Message, Notification, PasswordResetToken, User, db
from validators import (
    validate_change_password,
    validate_delete_account,
    validate_forgot_password,
    validate_login,
    validate_profile_update,
    validate_register_step,
    validate_reset_password,
)


ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    upload_folder = app.config.get("UPLOAD_FOLDER")
    if not upload_folder:
        upload_folder = os.path.join(app.root_path, "instance", "uploads")
        app.config["UPLOAD_FOLDER"] = upload_folder
    os.makedirs(upload_folder, exist_ok=True)
    os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)

    db.init_app(app)

    with app.app_context():
        db.create_all()
        if not Hobby.query.first():
            for name in [
                "Gardening",
                "Cooking",
                "Reading",
                "Music",
                "Sports",
                "Art",
                "Travel",
                "Technology",
                "Photography",
                "History",
                "Movies",
                "Gaming",
                "Crafts",
                "Yoga",
                "Walking",
                "Baking",
                "Fishing",
                "Pets",
            ]:
                db.session.add(Hobby(name=name))
            db.session.commit()

    @app.before_request
    def load_current_user():
        user_id = session.get("user_id")
        g.current_user = User.query.get(user_id) if user_id else None
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)

    @app.context_processor
    def inject_user():
        notification_count = 0
        if g.current_user:
            notification_count = Notification.query.filter_by(
                user_id=g.current_user.id, read_at=None
            ).count()

        def avatar_url(path):
            if not path:
                return url_for("static", filename="img/default_avatar.png")
            if path.startswith("uploads/"):
                filename = path.split("/", 1)[1]
                abs_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                if os.path.exists(abs_path):
                    return url_for("uploaded_file", filename=filename)
                return url_for("static", filename=path)
            return url_for("static", filename=path)

        def csrf_token():
            token = session.get("csrf_token", "")
            return Markup(f'<input type="hidden" name="csrf_token" value="{token}">')

        return {
            "current_user": g.current_user,
            "notification_count": notification_count,
            "avatar_url": avatar_url,
            "csrf_token": csrf_token,
        }

    def _is_valid_csrf():
        token = session.get("csrf_token", "")
        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        return bool(token and submitted and secrets.compare_digest(token, submitted))

    @app.before_request
    def csrf_protect():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not _is_valid_csrf():
                flash("Invalid CSRF token. Please try again.", "error")
                return redirect(request.referrer or url_for("index"))

    def login_required():
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not g.current_user:
                    flash("Please log in to continue.", "warning")
                    return redirect(url_for("login"))
                return func(*args, **kwargs)

            wrapper.__name__ = func.__name__
            return wrapper

        return decorator

    def admin_required():
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not g.current_user or not g.current_user.is_admin:
                    flash("Admin access required.", "warning")
                    return redirect(url_for("index"))
                return func(*args, **kwargs)

            wrapper.__name__ = func.__name__
            return wrapper

        return decorator

    def allowed_file(filename):
        _, ext = os.path.splitext(filename.lower())
        return ext in ALLOWED_EXTENSIONS

    def save_profile_picture(file_storage):
        if not file_storage or not file_storage.filename:
            return None
        if not allowed_file(file_storage.filename):
            return None
        filename = secure_filename(file_storage.filename)
        _, ext = os.path.splitext(filename)
        new_name = f"{uuid.uuid4().hex}{ext.lower()}"
        relative_path = os.path.join("uploads", new_name)
        abs_path = os.path.join(app.config["UPLOAD_FOLDER"], new_name)
        file_storage.save(abs_path)
        return relative_path.replace("\\", "/")

    def save_profile_picture_from_base64(data_url):
        if not data_url or not data_url.startswith("data:image/"):
            return None
        try:
            header, encoded = data_url.split(",", 1)
        except ValueError:
            return None
        if "image/png" in header:
            ext = ".png"
        elif "image/jpeg" in header or "image/jpg" in header:
            ext = ".jpg"
        elif "image/webp" in header:
            ext = ".webp"
        else:
            return None
        try:
            raw = base64.b64decode(encoded)
        except Exception:
            return None
        if len(raw) > 2 * 1024 * 1024:
            return None
        new_name = f"{uuid.uuid4().hex}{ext}"
        relative_path = os.path.join("uploads", new_name)
        abs_path = os.path.join(app.config["UPLOAD_FOLDER"], new_name)
        with open(abs_path, "wb") as handle:
            handle.write(raw)
        return relative_path.replace("\\", "/")

    def _is_safe_next(next_url):
        return (
            bool(next_url)
            and next_url.startswith("/")
            and not next_url.startswith("//")
            and "://" not in next_url
        )

    @app.errorhandler(413)
    def request_entity_too_large(_error):
        flash("File too large. Please upload an image under 2MB.", "error")
        return redirect(request.referrer or url_for("profile_edit"))

    @app.route("/uploads/<path:filename>")
    def uploaded_file(filename):
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/home")
    @login_required()
    def home():
        return render_template("home.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        errors = {}
        if request.method == "POST":
            is_valid, errors = validate_login(request.form)
            if is_valid:
                identifier = request.form.get("identifier", "").strip()
                password = request.form.get("password")
                user = User.query.filter(
                    or_(User.username == identifier, User.email == identifier.lower())
                ).first()
                if not user or not user.check_password(password):
                    errors["general"] = "Invalid credentials. Please try again."
                elif not user.is_active:
                    errors["general"] = "Your account is inactive. Please contact support."
                else:
                    session.clear()
                    session["user_id"] = user.id
                    flash("Welcome back!", "success")
                    return redirect(url_for("home"))
        return render_template("login.html", errors=errors, hide_nav=True)

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        errors = {}
        reset_link = None
        if request.method == "POST":
            is_valid, errors = validate_forgot_password(request.form)
            if is_valid:
                email = request.form.get("email").strip().lower()
                user = User.query.filter_by(email=email).first()
                if user:
                    raw_token, record = PasswordResetToken.create_for_user(user)
                    db.session.add(record)
                    db.session.commit()
                else:
                    raw_token = PasswordResetToken.generate_token()
                reset_link = url_for("reset_password", token=raw_token, _external=True)
                flash(
                    "If the email exists, a reset link has been generated.",
                    "success",
                )
        return render_template(
            "forgot_password.html", errors=errors, reset_link=reset_link, hide_nav=True
        )

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        errors = {}
        token_hash = PasswordResetToken.hash_token(token)
        record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
        if not record or not record.is_valid():
            flash("This reset link is invalid or expired.", "error")
            return render_template(
                "reset_password.html", errors=errors, invalid=True, hide_nav=True
            )

        if request.method == "POST":
            is_valid, errors = validate_reset_password(request.form)
            if is_valid:
                user = User.query.get(record.user_id)
                user.set_password(request.form.get("password"))
                record.used_at = datetime.utcnow()
                db.session.commit()
                flash("Password updated. Please log in.", "success")
                return redirect(url_for("login"))

        return render_template(
            "reset_password.html", errors=errors, invalid=False, hide_nav=True
        )

    def _init_register_session():
        session["register"] = {"step": 1, "data": {}}

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if "register" not in session:
            _init_register_session()

        reg_state = session.get("register", {})
        step = int(reg_state.get("step", 1))
        errors = {}

        if request.method == "POST":
            action = request.form.get("action", "next")
            step = int(request.form.get("step", step))

            if action == "back":
                step = max(1, step - 1)
                reg_state["step"] = step
                session["register"] = reg_state
                return render_template(
                    "register.html",
                    step=step,
                    data=reg_state["data"],
                    errors={},
                    hide_nav=True,
                )

            is_valid, errors = validate_register_step(step, request.form, request.files)
            if is_valid and step == 1:
                username = request.form.get("username").strip()
                if User.query.filter_by(username=username).first():
                    errors["username"] = "Username is already taken."
                is_valid = len(errors) == 0
            if is_valid and step == 2:
                email = request.form.get("email").strip().lower()
                if User.query.filter_by(email=email).first():
                    errors["email"] = "Email is already registered."
                is_valid = len(errors) == 0

            if is_valid:
                data = reg_state.get("data", {})
                if step == 1:
                    data["username"] = request.form.get("username").strip()
                    data["display_name"] = request.form.get("display_name").strip()
                elif step == 2:
                    data["email"] = request.form.get("email").strip().lower()
                elif step == 3:
                    data["password_hash"] = generate_password_hash(
                        request.form.get("password")
                    )
                elif step == 4:
                    data["age"] = request.form.get("age").strip()
                    data["date_of_birth"] = request.form.get("date_of_birth")
                elif step == 5:
                    required_fields = [
                        "username",
                        "email",
                        "password_hash",
                        "display_name",
                        "date_of_birth",
                    ]
                    if any(not data.get(field) for field in required_fields):
                        flash("Registration session expired. Please start again.", "error")
                        _init_register_session()
                        return redirect(url_for("register"))

                    profile_file = request.files.get("profile_picture")
                    saved_path = save_profile_picture(profile_file)
                    data["profile_picture_url"] = (
                        saved_path or "img/default_avatar.png"
                    )

                    is_admin = User.query.count() == 0
                    try:
                        dob = datetime.strptime(
                            data["date_of_birth"], "%Y-%m-%d"
                        ).date()
                    except ValueError:
                        flash("Please provide a valid date of birth.", "error")
                        reg_state["step"] = 4
                        session["register"] = reg_state
                        return redirect(url_for("register"))
                    user = User(
                        username=data["username"],
                        email=data["email"],
                        password_hash=data["password_hash"],
                        display_name=data["display_name"],
                        date_of_birth=dob,
                        privacy="public",
                        profile_picture_url=data["profile_picture_url"],
                        is_admin=is_admin,
                        is_active=True,
                    )
                    db.session.add(user)
                    db.session.commit()
                    session.clear()
                    session["user_id"] = user.id
                    flash("Account created successfully!", "success")
                    return redirect(url_for("profile_setup"))

                step = min(5, step + 1)
                reg_state["step"] = step
                reg_state["data"] = data
                session["register"] = reg_state
            else:
                reg_state["step"] = step
                session["register"] = reg_state

        return render_template(
            "register.html",
            step=step,
            data=reg_state.get("data", {}),
            errors=errors,
            hide_nav=True,
        )

    @app.route("/profile")
    @login_required()
    def profile():
        followers_count = Follow.query.filter_by(followed_id=g.current_user.id).count()
        following_count = Follow.query.filter_by(follower_id=g.current_user.id).count()
        return render_template(
            "profile_view.html",
            user=g.current_user,
            followers_count=followers_count,
            following_count=following_count,
        )

    @app.route("/users/<username>")
    def profile_public(username):
        user = User.query.filter_by(username=username).first_or_404()
        is_owner = g.current_user and g.current_user.id == user.id
        is_following = False
        is_followed_by = False
        can_message = False
        mutual_followers = []

        if g.current_user and not is_owner:
            is_following = (
                Follow.query.filter_by(
                    follower_id=g.current_user.id, followed_id=user.id
                ).first()
                is not None
            )
            is_followed_by = (
                Follow.query.filter_by(
                    follower_id=user.id, followed_id=g.current_user.id
                ).first()
                is not None
            )
            can_message = user.privacy == "public" or (is_following and is_followed_by)

            follower_ids = [
                row[0]
                for row in db.session.query(Follow.follower_id)
                .filter_by(followed_id=user.id)
                .all()
            ]
            current_following_ids = [
                row[0]
                for row in db.session.query(Follow.followed_id)
                .filter_by(follower_id=g.current_user.id)
                .all()
            ]
            mutual_ids = list(set(follower_ids).intersection(current_following_ids))
            if mutual_ids:
                mutual_followers = User.query.filter(User.id.in_(mutual_ids)).all()

        private_view = user.privacy == "private" and not is_owner
        followers_count = Follow.query.filter_by(followed_id=user.id).count()
        following_count = Follow.query.filter_by(follower_id=user.id).count()
        return render_template(
            "profile_public.html",
            user=user,
            private=private_view,
            is_owner=is_owner,
            is_following=is_following,
            is_followed_by=is_followed_by,
            can_message=can_message,
            mutual_followers=mutual_followers,
            followers_count=followers_count,
            following_count=following_count,
        )

    def _can_view_connections(target_user):
        return target_user.privacy == "public" or (
            g.current_user and g.current_user.id == target_user.id
        )

    @app.route("/users/<username>/followers")
    @login_required()
    def followers_list(username):
        user = User.query.filter_by(username=username).first_or_404()
        if not _can_view_connections(user):
            flash("Followers list is private.", "warning")
            return redirect(url_for("profile_public", username=username))
        follower_ids = [
            row[0]
            for row in db.session.query(Follow.follower_id)
            .filter_by(followed_id=user.id)
            .all()
        ]
        followers = User.query.filter(User.id.in_(follower_ids)).all() if follower_ids else []
        return render_template("followers_list.html", user=user, followers=followers)

    @app.route("/users/<username>/following")
    @login_required()
    def following_list(username):
        user = User.query.filter_by(username=username).first_or_404()
        if not _can_view_connections(user):
            flash("Following list is private.", "warning")
            return redirect(url_for("profile_public", username=username))
        following_ids = [
            row[0]
            for row in db.session.query(Follow.followed_id)
            .filter_by(follower_id=user.id)
            .all()
        ]
        following = User.query.filter(User.id.in_(following_ids)).all() if following_ids else []
        return render_template("following_list.html", user=user, following=following)

    @app.route("/profile/edit", methods=["GET", "POST"])
    @login_required()
    def profile_edit():
        errors = {}
        hobbies = Hobby.query.order_by(Hobby.name.asc()).all()
        if request.method == "POST":
            is_valid, errors = validate_profile_update(request.form, request.files)
            if is_valid:
                user = g.current_user
                new_username = request.form.get("username", "").strip()
                if new_username and new_username != user.username:
                    if User.query.filter_by(username=new_username).first():
                        errors["username"] = "Username is already taken."
                        return render_template(
                            "profile_edit.html",
                            user=g.current_user,
                            errors=errors,
                            hobbies=hobbies,
                            setup_mode=False,
                        )
                    user.username = new_username
                user.display_name = request.form.get("display_name").strip()
                user.bio = request.form.get("bio").strip()
                user.location = request.form.get("location")
                user.gender = request.form.get("gender") or None
                user.age_group = request.form.get("age_group") or None
                phone_raw = request.form.get("phone")
                if phone_raw is not None:
                    user.phone = phone_raw.strip()
                user.website = request.form.get("website").strip()
                user.privacy = request.form.get("privacy")
                dob_raw = request.form.get("date_of_birth")
                if dob_raw:
                    user.date_of_birth = datetime.strptime(dob_raw, "%Y-%m-%d").date()

                cropped_avatar = (request.form.get("cropped_avatar") or "").strip()
                if cropped_avatar:
                    new_picture = save_profile_picture_from_base64(cropped_avatar)
                else:
                    new_picture = save_profile_picture(request.files.get("profile_picture"))
                if new_picture:
                    user.profile_picture_url = new_picture

                selected_ids = request.form.getlist("hobbies")
                if selected_ids:
                    user.hobbies = Hobby.query.filter(
                        Hobby.id.in_(selected_ids)
                    ).all()
                else:
                    user.hobbies = []

                db.session.commit()
                flash("Profile updated.", "success")
                return redirect(url_for("profile"))
        return render_template(
            "profile_edit.html",
            user=g.current_user,
            errors=errors,
            hobbies=hobbies,
            setup_mode=False,
        )

    @app.route("/profile/setup", methods=["GET", "POST"])
    @login_required()
    def profile_setup():
        errors = {}
        hobbies = Hobby.query.order_by(Hobby.name.asc()).all()
        if request.method == "POST":
            is_valid, errors = validate_profile_update(request.form, request.files)
            if is_valid:
                user = g.current_user
                new_username = request.form.get("username", "").strip()
                if new_username and new_username != user.username:
                    if User.query.filter_by(username=new_username).first():
                        errors["username"] = "Username is already taken."
                        return render_template(
                            "profile_edit.html",
                            user=g.current_user,
                            errors=errors,
                            hobbies=hobbies,
                            setup_mode=True,
                        )
                    user.username = new_username
                user.display_name = request.form.get("display_name").strip()
                user.bio = request.form.get("bio").strip()
                user.location = request.form.get("location")
                user.gender = request.form.get("gender") or None
                user.age_group = request.form.get("age_group") or None
                phone_raw = request.form.get("phone")
                if phone_raw is not None:
                    user.phone = phone_raw.strip()
                user.website = request.form.get("website").strip()
                user.privacy = request.form.get("privacy")
                dob_raw = request.form.get("date_of_birth")
                if dob_raw:
                    user.date_of_birth = datetime.strptime(dob_raw, "%Y-%m-%d").date()

                cropped_avatar = (request.form.get("cropped_avatar") or "").strip()
                if cropped_avatar:
                    new_picture = save_profile_picture_from_base64(cropped_avatar)
                else:
                    new_picture = save_profile_picture(request.files.get("profile_picture"))
                if new_picture:
                    user.profile_picture_url = new_picture

                selected_ids = request.form.getlist("hobbies")
                if selected_ids:
                    user.hobbies = Hobby.query.filter(
                        Hobby.id.in_(selected_ids)
                    ).all()
                else:
                    user.hobbies = []

                db.session.commit()
                flash("Profile updated.", "success")
                return redirect(url_for("profile"))
        return render_template(
            "profile_edit.html",
            user=g.current_user,
            errors=errors,
            hobbies=hobbies,
            setup_mode=True,
        )

    @app.route("/api/onemap/search")
    @login_required()
    def onemap_search():
        query = (request.args.get("q") or "").strip()
        if len(query) < 2:
            return jsonify({"results": []})
        params = urlencode(
            {
                "searchVal": query,
                "returnGeom": "N",
                "getAddrDetails": "Y",
                "pageNum": "1",
            }
        )
        url = f"https://www.onemap.gov.sg/api/common/elastic/search?{params}"
        try:
            with urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
        except Exception:
            return jsonify({"results": []})
        results = []
        for item in data.get("results", [])[:10]:
            address = item.get("SEARCHVAL") or item.get("ADDRESS") or ""
            if address:
                results.append(address.title())
        return jsonify({"results": results})

    @app.route("/search")
    @login_required()
    def search_users():
        query = (request.args.get("q") or "").strip()
        results = []
        follow_map = {}
        message_map = {}

        if query:
            results = (
                User.query.filter(
                    or_(
                        User.username.ilike(f"%{query}%"),
                        User.display_name.ilike(f"%{query}%"),
                    )
                )
                .order_by(User.username.asc())
                .limit(20)
                .all()
            )

        for user in results:
            if user.id == g.current_user.id:
                continue
            is_following = (
                Follow.query.filter_by(
                    follower_id=g.current_user.id, followed_id=user.id
                ).first()
                is not None
            )
            is_followed_by = (
                Follow.query.filter_by(
                    follower_id=user.id, followed_id=g.current_user.id
                ).first()
                is not None
            )
            can_message = user.privacy == "public" or (is_following and is_followed_by)
            follow_map[user.id] = is_following
            message_map[user.id] = can_message

        return render_template(
            "search.html",
            query=query,
            results=results,
            follow_map=follow_map,
            message_map=message_map,
        )

    @app.route("/notifications")
    @login_required()
    def notifications():
        items = Notification.query.filter_by(user_id=g.current_user.id).order_by(
            Notification.created_at.desc()
        ).all()
        Notification.query.filter_by(user_id=g.current_user.id, read_at=None).update(
            {Notification.read_at: datetime.utcnow()}
        )
        db.session.commit()
        return render_template("notifications.html", items=items)

    @app.route("/forums")
    @login_required()
    def forums():
        return render_template("placeholder.html", title="Forums")

    @app.route("/events")
    @login_required()
    def events():
        return render_template("placeholder.html", title="Events")

    @app.route("/games")
    @login_required()
    def games():
        return render_template("placeholder.html", title="Games")

    @app.route("/messages")
    @login_required()
    def messages_page():
        return render_template("placeholder.html", title="Messages")

    @app.route("/settings")
    @login_required()
    def settings():
        return render_template("settings.html")

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required()
    def change_password():
        errors = {}
        if request.method == "POST":
            is_valid, errors = validate_change_password(request.form)
            if is_valid:
                if not g.current_user.check_password(request.form.get("old_password")):
                    errors["old_password"] = "Current password is incorrect."
                else:
                    g.current_user.set_password(request.form.get("new_password"))
                    db.session.commit()
                    flash("Password updated.", "success")
                    return redirect(url_for("profile"))
        return render_template("change_password.html", errors=errors)

    @app.route("/delete-account", methods=["GET", "POST"])
    @login_required()
    def delete_account():
        errors = {}
        if request.method == "POST":
            is_valid, errors = validate_delete_account(request.form, g.current_user)
            if is_valid:
                if not g.current_user.check_password(request.form.get("password")):
                    errors["password"] = "Password is incorrect."
                else:
                    PasswordResetToken.query.filter_by(user_id=g.current_user.id).delete()
                    db.session.delete(g.current_user)
                    db.session.commit()
                    session.clear()
                    flash("Your account has been deleted.", "success")
                    return redirect(url_for("index"))
        return render_template("confirm_delete.html", errors=errors)

    @app.route("/users/<username>/follow", methods=["POST"])
    @login_required()
    def follow_user(username):
        user = User.query.filter_by(username=username).first_or_404()
        if user.id == g.current_user.id:
            flash("You cannot follow yourself.", "warning")
            return redirect(url_for("profile_public", username=username))
        if not Follow.query.filter_by(
            follower_id=g.current_user.id, followed_id=user.id
        ).first():
            db.session.add(
                Follow(follower_id=g.current_user.id, followed_id=user.id)
            )
            db.session.add(
                Notification(
                    user_id=user.id,
                    type="follow",
                    message=f"{g.current_user.display_name or g.current_user.username} followed you.",
                )
            )
            db.session.commit()
            flash("You are now following this user.", "success")
        next_url = (request.form.get("next") or "").strip()
        if _is_safe_next(next_url):
            return redirect(next_url)
        return redirect(url_for("profile_public", username=username))

    @app.route("/users/<username>/unfollow", methods=["POST"])
    @login_required()
    def unfollow_user(username):
        user = User.query.filter_by(username=username).first_or_404()
        removed = Follow.query.filter_by(
            follower_id=g.current_user.id, followed_id=user.id
        ).delete(synchronize_session=False)
        if removed:
            db.session.add(
                Notification(
                    user_id=user.id,
                    type="unfollow",
                    message=(
                        f"{g.current_user.display_name or g.current_user.username} "
                        "unfollowed you."
                    ),
                )
            )
        db.session.commit()
        flash("You have unfollowed this user.", "success")
        next_url = (request.form.get("next") or "").strip()
        if _is_safe_next(next_url):
            return redirect(next_url)
        return redirect(url_for("profile_public", username=username))

    @app.route("/users/<username>/message", methods=["POST"])
    @login_required()
    def message_user(username):
        user = User.query.filter_by(username=username).first_or_404()
        if user.id == g.current_user.id:
            flash("You cannot message yourself.", "warning")
            return redirect(url_for("profile_public", username=username))

        is_following = (
            Follow.query.filter_by(
                follower_id=g.current_user.id, followed_id=user.id
            ).first()
            is not None
        )
        is_followed_by = (
            Follow.query.filter_by(
                follower_id=user.id, followed_id=g.current_user.id
            ).first()
            is not None
        )
        can_message = user.privacy == "public" or (is_following and is_followed_by)
        if not can_message:
            flash("You can only message mutual followers for private profiles.", "warning")
            return redirect(url_for("profile_public", username=username))

        body = (request.form.get("message") or "").strip()
        if not body:
            flash("Please enter a message.", "warning")
            return redirect(url_for("profile_public", username=username))
        if len(body) > 500:
            flash("Message must be 500 characters or less.", "warning")
            return redirect(url_for("profile_public", username=username))

        db.session.add(
            Message(sender_id=g.current_user.id, receiver_id=user.id, body=body)
        )
        db.session.commit()
        flash("Message sent.", "success")
        return redirect(url_for("profile_public", username=username))

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
