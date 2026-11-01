import os, uuid, hashlib, hmac, json
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file, current_app, has_request_context
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SelectField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "txt", "png", "jpg", "jpeg"}
MAX_FILE_BYTES = 10 * 1024 * 1024

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_active_account = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.is_active_account

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(80), unique=True, nullable=False)
    category = db.Column(db.String(80), nullable=False, default="General")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    owner = db.relationship("User", backref="owned_documents")

class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    permission = db.Column(db.String(10), nullable=False)  # read or edit
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (db.UniqueConstraint("document_id", "user_id", name="uq_document_user"),)

class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(60), nullable=False)
    document_id = db.Column(db.Integer, nullable=True)
    target_user_id = db.Column(db.Integer, nullable=True)
    detail = db.Column(db.Text, nullable=False, default="{}")
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    event_hash = db.Column(db.String(64), nullable=False)

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=254)])
    password = PasswordField("Password", validators=[DataRequired()])

class GrantForm(FlaskForm):
    email = StringField("User email", validators=[DataRequired(), Email(), Length(max=254)])
    permission = SelectField("Permission", choices=[("read", "Read"), ("edit", "Edit")], validators=[DataRequired()])

class RenameForm(FlaskForm):
    name = StringField("Document name", validators=[DataRequired(), Length(max=255)])
    category = StringField("Category", validators=[DataRequired(), Length(max=80)])

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def utcnow():
    return datetime.now(timezone.utc)

def log_event(action, document_id=None, target_user_id=None, detail=None, actor_id=None):
    """Append an HMAC-protected event. HMAC key must be kept outside the database."""
    key = current_app.config["AUDIT_HMAC_KEY"].encode("utf-8")
    previous = db.session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    previous_hash = previous.event_hash if previous else "GENESIS"
    event_time = datetime.now(timezone.utc).replace(tzinfo=None)
    authenticated_actor = current_user.id if has_request_context() and current_user.is_authenticated else None
    ip_address = (request.headers.get("X-Forwarded-For") or request.remote_addr) if has_request_context() else None
    payload = {
        "actor_id": actor_id if actor_id is not None else authenticated_actor,
        "action": action, "document_id": document_id, "target_user_id": target_user_id,
        "detail": json.dumps(detail or {}, sort_keys=True, separators=(",", ":")),
        "ip_address": ip_address,
        "created_at": event_time.isoformat(), "previous_hash": previous_hash
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    event_hash = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    event = AuditEvent(
        actor_id=payload["actor_id"], action=action, document_id=document_id,
        target_user_id=target_user_id, detail=payload["detail"], ip_address=ip_address,
        created_at=event_time, previous_hash=previous_hash, event_hash=event_hash
    )
    db.session.add(event)
    db.session.flush()

def verify_audit_chain():
    key = current_app.config["AUDIT_HMAC_KEY"].encode("utf-8")
    previous_hash = "GENESIS"
    for event in AuditEvent.query.order_by(AuditEvent.id.asc()).all():
        payload = {
            "actor_id": event.actor_id, "action": event.action, "document_id": event.document_id,
            "target_user_id": event.target_user_id, "detail": event.detail,
            "ip_address": event.ip_address, "created_at": event.created_at.isoformat(),
            "previous_hash": previous_hash
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        if event.previous_hash != previous_hash or not hmac.compare_digest(expected, event.event_hash):
            return False
        previous_hash = event.event_hash
    return True

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            log_event("DENIED_ADMIN_ROUTE", detail={"path": request.path})
            db.session.commit()
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def get_document_access(document_id, required="read"):
    """The central server-side authorisation check used by every document route."""
    document = db.session.get(Document, document_id)
    if document is None:
        return None, False
    if current_user.role == "admin" or document.owner_id == current_user.id:
        return document, True
    grant = Grant.query.filter_by(document_id=document.id, user_id=current_user.id).first()
    allowed = bool(grant and (grant.permission == "edit" or required == "read"))
    return document, allowed

def document_access_required(required="read"):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(document_id, *args, **kwargs):
            document, allowed = get_document_access(document_id, required)
            if not allowed:
                log_event("DENIED_DOCUMENT_ACCESS", document_id=document_id, detail={"required": required, "path": request.path})
                db.session.commit()
                abort(404)  # Do not reveal whether another user's document exists.
            return fn(document_id, document=document, *args, **kwargs)
        return wrapper
    return decorator

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("TRUSTVAULT_SECRET_KEY", "dev-only-change-this-secret"),
        AUDIT_HMAC_KEY=os.environ.get("TRUSTVAULT_AUDIT_KEY", "dev-only-change-this-audit-key"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///trustvault.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=MAX_FILE_BYTES,
        UPLOAD_FOLDER=os.environ.get("TRUSTVAULT_UPLOAD_DIR", str(Path(app.instance_path) / "private_uploads")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        REMEMBER_COOKIE_HTTPONLY=True,
        WTF_CSRF_TIME_LIMIT=None,
    )
    if test_config:
        app.config.update(test_config)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    csrf.init_app(app)

    @app.errorhandler(413)
    def too_large(_):
        flash("File is too large. Maximum size is 10 MB.", "error")
        return redirect(url_for("dashboard")), 413

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.strip().lower()).first()
            if user and user.is_active_account and user.check_password(form.password.data):
                login_user(user)
                log_event("LOGIN_SUCCESS", detail={"email": user.email})
                db.session.commit()
                return redirect(url_for("dashboard"))
            log_event("LOGIN_FAILED", detail={"email": form.email.data.strip().lower()}, actor_id=None)
            db.session.commit()
            flash("Invalid email or password.", "error")
        return render_template("login.html", form=form)

    @app.post("/logout")
    @login_required
    def logout():
        log_event("LOGOUT")
        db.session.commit()
        logout_user()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        if current_user.role == "admin":
            docs = Document.query.order_by(Document.created_at.desc()).all()
        else:
            granted_ids = db.session.query(Grant.document_id).filter_by(user_id=current_user.id)
            docs = Document.query.filter(or_(Document.owner_id == current_user.id, Document.id.in_(granted_ids))).order_by(Document.created_at.desc()).all()
        return render_template("dashboard.html", documents=docs)

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if current_user.role not in ("owner", "admin"):
            abort(403)
        if request.method == "POST":
            uploaded = request.files.get("file")
            category = request.form.get("category", "General").strip()[:80] or "General"
            if not uploaded or not uploaded.filename:
                flash("Choose a file first.", "error")
                return redirect(url_for("upload"))
            original = secure_filename(uploaded.filename)
            if not original or not allowed_file(original):
                log_event("UPLOAD_REJECTED", detail={"filename": uploaded.filename})
                db.session.commit()
                flash("File type not allowed.", "error")
                return redirect(url_for("upload"))
            stored = uuid.uuid4().hex
            path = Path(current_app.config["UPLOAD_FOLDER"]) / stored
            uploaded.save(path)
            doc = Document(original_name=original, stored_name=stored, category=category, owner_id=current_user.id)
            db.session.add(doc)
            db.session.flush()
            log_event("UPLOAD", document_id=doc.id, detail={"filename": original, "category": category})
            db.session.commit()
            flash("Document uploaded privately.", "success")
            return redirect(url_for("dashboard"))
        return render_template("upload.html")

    @app.get("/documents/<int:document_id>/download")
    @document_access_required("read")
    def download(document_id, document):
        path = Path(current_app.config["UPLOAD_FOLDER"]) / document.stored_name
        if not path.is_file():
            abort(404)
        log_event("DOWNLOAD", document_id=document.id, detail={"filename": document.original_name})
        db.session.commit()
        return send_file(path, as_attachment=True, download_name=document.original_name)

    @app.route("/documents/<int:document_id>/edit", methods=["GET", "POST"])
    @document_access_required("edit")
    def edit_document(document_id, document):
        form = RenameForm(data={"name": document.original_name, "category": document.category})
        if form.validate_on_submit():
            old = {"name": document.original_name, "category": document.category}
            document.original_name = secure_filename(form.name.data) or document.original_name
            document.category = form.category.data.strip()
            document.updated_at = utcnow()
            log_event("DOCUMENT_EDIT", document_id=document.id, detail={"before": old, "after": {"name": document.original_name, "category": document.category}})
            db.session.commit()
            flash("Document details updated.", "success")
            return redirect(url_for("dashboard"))
        return render_template("edit.html", document=document, form=form)

    @app.post("/documents/<int:document_id>/delete")
    @document_access_required("edit")
    def delete_document(document_id, document):
        path = Path(current_app.config["UPLOAD_FOLDER"]) / document.stored_name
        log_event("DELETE", document_id=document.id, detail={"filename": document.original_name})
        Grant.query.filter_by(document_id=document.id).delete()
        db.session.delete(document)
        db.session.commit()
        if path.exists():
            path.unlink()
        flash("Document deleted.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/documents/<int:document_id>/permissions", methods=["GET", "POST"])
    @login_required
    def permissions(document_id):
        document = db.session.get(Document, document_id)
        if not document or (current_user.role != "admin" and document.owner_id != current_user.id):
            log_event("DENIED_PERMISSION_MANAGEMENT", document_id=document_id)
            db.session.commit()
            abort(404)
        form = GrantForm()
        if form.validate_on_submit():
            target = User.query.filter_by(email=form.email.data.strip().lower()).first()
            if not target:
                flash("No user found with that email.", "error")
            elif target.id == document.owner_id:
                flash("The owner already has full control.", "error")
            else:
                grant = Grant.query.filter_by(document_id=document.id, user_id=target.id).first()
                old = grant.permission if grant else None
                if grant:
                    grant.permission = form.permission.data
                else:
                    db.session.add(Grant(document_id=document.id, user_id=target.id, permission=form.permission.data))
                log_event("PERMISSION_GRANT" if old is None else "PERMISSION_CHANGE", document_id=document.id, target_user_id=target.id, detail={"old": old, "new": form.permission.data})
                db.session.commit()
                flash("Permission saved.", "success")
                return redirect(url_for("permissions", document_id=document.id))
        grants = Grant.query.filter_by(document_id=document.id).all()
        return render_template("permissions.html", document=document, grants=grants, form=form)

    @app.post("/documents/<int:document_id>/permissions/<int:grant_id>/revoke")
    @login_required
    def revoke_permission(document_id, grant_id):
        document = db.session.get(Document, document_id)
        if not document or (current_user.role != "admin" and document.owner_id != current_user.id):
            log_event("DENIED_PERMISSION_REVOKE", document_id=document_id)
            db.session.commit()
            abort(404)
        grant = Grant.query.filter_by(id=grant_id, document_id=document.id).first_or_404()
        target_id = grant.user_id
        old_permission = grant.permission
        db.session.delete(grant)
        log_event("PERMISSION_REVOKE", document_id=document.id, target_user_id=target_id, detail={"old": old_permission})
        db.session.commit()
        flash("Access revoked immediately.", "success")
        return redirect(url_for("permissions", document_id=document.id))

    @app.route("/admin/activity")
    @admin_required
    def admin_activity():
        events = AuditEvent.query.order_by(AuditEvent.id.desc()).limit(300).all()
        return render_template("activity.html", events=events, chain_valid=verify_audit_chain())

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        users = User.query.order_by(User.id.asc()).all()
        return render_template("users.html", users=users)

    @app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
    @admin_required
    def toggle_user(user_id):
        user = db.session.get(User, user_id)
        if not user or user.id == current_user.id:
            abort(404)
        user.is_active_account = not user.is_active_account
        log_event("USER_DISABLED" if not user.is_active_account else "USER_ENABLED", target_user_id=user.id)
        db.session.commit()
        return redirect(url_for("admin_users"))

    @app.route("/admin/audit/verify")
    @admin_required
    def audit_verify():
        return {"audit_chain_valid": verify_audit_chain()}

    @app.errorhandler(403)
    def forbidden(_):
        return render_template("error.html", code=403, message="You are not allowed to perform this action."), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, message="The requested resource was not found."), 404

    with app.app_context():
        db.create_all()
    return app

app = create_app()
