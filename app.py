import os
try:
    import magic
except ImportError:
    magic = None
import zipfile
from io import BytesIO
import uuid
import hashlib
import hmac
import json

from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort, send_file, current_app, has_request_context
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, event as sqlalchemy_event
from sqlalchemy.orm import Session
from audit_checkpoint import write_checkpoint, read_checkpoint
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)

from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email, Length

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)

ALLOWED_EXTENSIONS = {
    "pdf", "docx", "xlsx", "txt", "png", "jpg", "jpeg"
}

MAX_FILE_BYTES = 10 * 1024 * 1024


# ---------------- DATABASE MODELS ----------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_active_account = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

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
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    owner = db.relationship("User", backref="owned_documents")


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=False,
        index=True
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True
    )
    permission = db.Column(db.String(10), nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "user_id",
            name="uq_document_user"
        ),
    )


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )
    action = db.Column(db.String(60), nullable=False)
    document_id = db.Column(db.Integer, nullable=True)
    target_user_id = db.Column(db.Integer, nullable=True)
    detail = db.Column(db.Text, nullable=False, default="{}")
    ip_address = db.Column(db.String(64), nullable=True)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    previous_hash = db.Column(db.String(64), nullable=False)
    event_hash = db.Column(db.String(64), nullable=False)


# ---------------- FORMS ----------------

class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=254)]
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired()]
    )


class GrantForm(FlaskForm):
    email = StringField(
        "User email",
        validators=[DataRequired(), Email(), Length(max=254)]
    )

    permission = SelectField(
        "Permission",
        choices=[("read", "Read"), ("edit", "Edit")],
        validators=[DataRequired()]
    )


class RenameForm(FlaskForm):
    name = StringField(
        "Document name",
        validators=[DataRequired(), Length(max=255)]
    )

    category = StringField(
        "Category",
        validators=[DataRequired(), Length(max=80)]
    )


# ---------------- LOGIN ----------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def utcnow():
    return datetime.now(timezone.utc)


# ---------------- AUDIT LOGGING ----------------

def log_event(
    action,
    document_id=None,
    target_user_id=None,
    detail=None,
    actor_id=None
):
    key = current_app.config["AUDIT_HMAC_KEY"].encode("utf-8")

    previous = (
        db.session.query(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .first()
    )

    previous_hash = previous.event_hash if previous else "GENESIS"

    event_time = datetime.now(timezone.utc).replace(tzinfo=None)

    authenticated_actor = (
        current_user.id
        if has_request_context() and current_user.is_authenticated
        else None
    )

    ip_address = (
        request.remote_addr
        if has_request_context()
        else None
    )

    payload = {
        "actor_id": actor_id if actor_id is not None else authenticated_actor,
        "action": action,
        "document_id": document_id,
        "target_user_id": target_user_id,
        "detail": json.dumps(
            detail or {},
            sort_keys=True,
            separators=(",", ":")
        ),
        "ip_address": ip_address,
        "created_at": event_time.isoformat(),
        "previous_hash": previous_hash
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":")
    )

    event_hash = hmac.new(
        key,
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    event = AuditEvent(
        actor_id=payload["actor_id"],
        action=action,
        document_id=document_id,
        target_user_id=target_user_id,
        detail=payload["detail"],
        ip_address=ip_address,
        created_at=event_time,
        previous_hash=previous_hash,
        event_hash=event_hash
    )

    db.session.add(event)
    db.session.flush()

    db.session().info["pending_audit_checkpoint"] = {
        "file_path": current_app.config["AUDIT_CHECKPOINT_FILE"],
        "last_event_id": event.id,
        "last_event_hash": event.event_hash,
        "key": current_app.config["AUDIT_HMAC_KEY"],
    }


@sqlalchemy_event.listens_for(Session, "after_commit")
def update_audit_checkpoint(session):
    pending = session.info.pop("pending_audit_checkpoint", None)

    if pending:
        write_checkpoint(
            pending["file_path"],
            pending["last_event_id"],
            pending["last_event_hash"],
            pending["key"],
        )


@sqlalchemy_event.listens_for(Session, "after_rollback")
def clear_pending_audit_checkpoint(session):
    session.info.pop("pending_audit_checkpoint", None)


# ---------------- AUDIT VERIFICATION ----------------

def verify_audit_chain_details():

    key = current_app.config["AUDIT_HMAC_KEY"].encode("utf-8")
    previous_hash = "GENESIS"

    events = AuditEvent.query.order_by(
        AuditEvent.id.asc()
    ).all()

    for event in events:

        if event.previous_hash != previous_hash:
            return {
                "valid": False,
                "reason": "PREVIOUS_HASH_MISMATCH",
                "event_id": event.id
            }

        payload = {
            "actor_id": event.actor_id,
            "action": event.action,
            "document_id": event.document_id,
            "target_user_id": event.target_user_id,
            "detail": event.detail,
            "ip_address": event.ip_address,
            "created_at": event.created_at.isoformat(),
            "previous_hash": previous_hash
        }

        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":")
        )

        expected = hmac.new(
            key,
            canonical.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            expected,
            event.event_hash
        ):
            return {
                "valid": False,
                "reason": "HMAC_MISMATCH",
                "event_id": event.id
            }

        previous_hash = event.event_hash

    checkpoint_path = Path(
        current_app.config["AUDIT_CHECKPOINT_FILE"]
    )

    if not events:
        return {
            "valid": not checkpoint_path.exists(),
            "reason": "EMPTY_CHAIN"
        }

    checkpoint = read_checkpoint(
        checkpoint_path,
        current_app.config["AUDIT_HMAC_KEY"]
    )

    if checkpoint is None:
        return {
            "valid": False,
            "reason": "CHECKPOINT_INVALID"
        }

    if (
        checkpoint["last_event_id"] != events[-1].id
        or not hmac.compare_digest(
            checkpoint["last_event_hash"],
            events[-1].event_hash
        )
    ):
        return {
            "valid": False,
            "reason": "CHECKPOINT_MISMATCH"
        }

    return {
        "valid": True,
        "reason": "OK",
        "event_id": None
    }


def verify_audit_chain():
    return verify_audit_chain_details()["valid"]
# ---------------- AUTHORIZATION ----------------

def admin_required(fn):

    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):

        if current_user.role != "admin":

            log_event(
                "DENIED_ADMIN_ROUTE",
                detail={"path": request.path}
            )

            db.session.commit()
            abort(403)

        return fn(*args, **kwargs)

    return wrapper


def get_document_access(document_id, required="read"):

    document = db.session.get(Document, document_id)

    if document is None:
        return None, False

    if (
        current_user.role == "admin"
        or document.owner_id == current_user.id
    ):
        return document, True

    grant = Grant.query.filter_by(
        document_id=document.id,
        user_id=current_user.id
    ).first()

    if grant is None:
        return document, False

    if grant.permission not in ("read", "edit"):
        return document, False

    if grant.permission == "edit":
        return document, True

    if grant.permission == "read" and required == "read":
        return document, True

    return document, False


def document_access_required(required="read"):

    def decorator(fn):

        @wraps(fn)
        @login_required
        def wrapper(document_id, *args, **kwargs):

            document, allowed = get_document_access(
                document_id,
                required
            )

            if not allowed:

                log_event(
                    "DENIED_DOCUMENT_ACCESS",
                    document_id=document_id,
                    detail={
                        "required": required,
                        "path": request.path
                    }
                )

                db.session.commit()
                abort(404)

            return fn(
                document_id,
                document=document,
                *args,
                **kwargs
            )

        return wrapper

    return decorator


# ---------------- FILE VALIDATION ----------------

def allowed_file(filename, uploaded_file):

    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        return False

    uploaded_file.stream.seek(0)

    file_data = uploaded_file.stream.read(
        MAX_FILE_BYTES + 1
    )

    uploaded_file.stream.seek(0)

    if not file_data or len(file_data) > MAX_FILE_BYTES:
        return False

    try:
        if magic is None:
            return False

        detected_type = magic.from_buffer(
            file_data[:8192],
            mime=True
        )
    except Exception:
        return False

    if extension == "pdf":
        return (
            detected_type == "application/pdf"
            and file_data.startswith(b"%PDF-")
        )

    image_types = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg"
    }

    if extension in image_types:
        return detected_type == image_types[extension]

    if extension in ("docx", "xlsx"):

        if not zipfile.is_zipfile(BytesIO(file_data)):
            return False

        try:
            with zipfile.ZipFile(BytesIO(file_data)) as archive:

                names = archive.namelist()

                if extension == "docx":
                    return (
                        "[Content_Types].xml" in names
                        and "word/document.xml" in names
                    )

                return (
                    "[Content_Types].xml" in names
                    and "xl/workbook.xml" in names
                )

        except (zipfile.BadZipFile, OSError):
            return False

    if extension == "txt":
        return (
            detected_type in (
                "text/plain",
                "application/octet-stream"
            )
            and b"\x00" not in file_data
        )

    return False


# ---------------- APPLICATION ----------------

def create_app(test_config=None):

    app = Flask(__name__)

    is_production = os.environ.get(
        "APP_ENV", "development"
    ).lower() == "production"

    secret_key = os.environ.get(
        "TRUSTVAULT_SECRET_KEY",
        "dev-only-change-this-secret"
    )

    audit_key = os.environ.get(
        "TRUSTVAULT_AUDIT_KEY",
        "dev-only-change-this-audit-key"
    )

    if is_production and not test_config:

        if len(secret_key) < 32:
            raise RuntimeError(
                "A strong TRUSTVAULT_SECRET_KEY of at least 32 characters is required."
            )

        if len(audit_key) < 32:
            raise RuntimeError(
                "A strong TRUSTVAULT_AUDIT_KEY of at least 32 characters is required."
            )

        if secret_key == audit_key:
            raise RuntimeError(
                "Use different keys for Flask sessions and audit HMAC."
            )

    app.config.update(

        SECRET_KEY=secret_key,

        AUDIT_HMAC_KEY=audit_key,

        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL",
            "sqlite:///trustvault.db"
        ),

        SQLALCHEMY_TRACK_MODIFICATIONS=False,

        MAX_CONTENT_LENGTH=MAX_FILE_BYTES,

        UPLOAD_FOLDER=os.environ.get(
            "TRUSTVAULT_UPLOAD_DIR",
            str(Path(app.instance_path) / "private_uploads")
        ),

        AUDIT_CHECKPOINT_FILE=os.environ.get(
            "TRUSTVAULT_AUDIT_CHECKPOINT_FILE",
            str(Path(app.instance_path) / "audit_checkpoint.json")
        ),

        SESSION_COOKIE_HTTPONLY=True,

        SESSION_COOKIE_SAMESITE="Lax",

        SESSION_COOKIE_SECURE=(
            os.environ.get("COOKIE_SECURE", "0") == "1"
        ),

        REMEMBER_COOKIE_HTTPONLY=True,

        WTF_CSRF_TIME_LIMIT=None
    )

    if test_config:
        app.config.update(test_config)

    Path(app.config["UPLOAD_FOLDER"]).mkdir(
        parents=True,
        exist_ok=True
    )

    Path(app.instance_path).mkdir(
        parents=True,
        exist_ok=True
    )

    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "login"

    csrf.init_app(app)

    limiter.init_app(app)


    # ---------------- ERROR HANDLERS ----------------

    @app.errorhandler(413)
    def too_large(_):

        flash(
            "File is too large. Maximum size is 10 MB.",
            "error"
        )

        return redirect(url_for("dashboard")), 413


    @app.errorhandler(403)
    def forbidden(_):

        return render_template(
            "error.html",
            code=403,
            message="You are not allowed to perform this action."
        ), 403


    @app.errorhandler(404)
    def not_found(_):

        return render_template(
            "error.html",
            code=404,
            message="The requested resource was not found."
        ), 404


    # ---------------- HOME ----------------

    @app.route("/")
    def index():

        return redirect(
            url_for(
                "dashboard"
                if current_user.is_authenticated
                else "login"
            )
        )


    # ---------------- LOGIN ----------------

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def login():

        form = LoginForm()

        if form.validate_on_submit():

            email = form.email.data.strip().lower()

            user = User.query.filter_by(email=email).first()

            if (
                user
                and user.is_active_account
                and user.check_password(form.password.data)
            ):

                login_user(user)

                log_event(
                    "LOGIN_SUCCESS",
                    detail={"email": user.email}
                )

                db.session.commit()

                return redirect(url_for("dashboard"))

            log_event(
                "LOGIN_FAILED",
                detail={"email": email},
                actor_id=None
            )

            db.session.commit()

            flash(
                "Invalid email or password.",
                "error"
            )

        return render_template(
            "login.html",
            form=form
        )
    # ---------------- LOGOUT ----------------

    @app.post("/logout")
    @login_required
    def logout():

        log_event("LOGOUT")
        db.session.commit()

        logout_user()

        return redirect(url_for("login"))


    # ---------------- DASHBOARD ----------------

    @app.route("/dashboard")
    @login_required
    def dashboard():

        if current_user.role == "admin":

            docs = Document.query.order_by(
                Document.created_at.desc()
            ).all()

        else:

            granted_ids = db.session.query(
                Grant.document_id
            ).filter_by(
                user_id=current_user.id
            )

            docs = Document.query.filter(
                or_(
                    Document.owner_id == current_user.id,
                    Document.id.in_(granted_ids)
                )
            ).order_by(
                Document.created_at.desc()
            ).all()

        return render_template(
            "dashboard.html",
            documents=docs
        )


    # ---------------- UPLOAD ----------------

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():

        if current_user.role not in ("owner", "admin"):
            abort(403)

        if request.method == "POST":

            uploaded = request.files.get("file")

            category = (
                request.form.get("category", "General")
                .strip()[:80]
                or "General"
            )

            if not uploaded or not uploaded.filename:

                flash(
                    "Choose a file first.",
                    "error"
                )

                return redirect(url_for("upload"))

            original = secure_filename(uploaded.filename)

            if not original or not allowed_file(original, uploaded):

                log_event(
                    "UPLOAD_REJECTED",
                    detail={"filename": uploaded.filename}
                )

                db.session.commit()

                flash(
                    "File type not allowed.",
                    "error"
                )

                return redirect(url_for("upload"))

            stored = uuid.uuid4().hex

            path = (
                Path(current_app.config["UPLOAD_FOLDER"])
                / stored
            )

            uploaded.save(path)

            doc = Document(
                original_name=original,
                stored_name=stored,
                category=category,
                owner_id=current_user.id
            )

            db.session.add(doc)
            db.session.flush()

            log_event(
                "UPLOAD",
                document_id=doc.id,
                detail={
                    "filename": original,
                    "category": category
                }
            )

            db.session.commit()

            flash(
                "Document uploaded privately.",
                "success"
            )

            return redirect(url_for("dashboard"))

        return render_template("upload.html")


    # ---------------- DOWNLOAD ----------------

    @app.get("/documents/<int:document_id>/download")
    @document_access_required("read")
    def download(document_id, document):

        path = (
            Path(current_app.config["UPLOAD_FOLDER"])
            / document.stored_name
        )

        if not path.is_file():
            abort(404)

        log_event(
            "DOWNLOAD",
            document_id=document.id,
            detail={"filename": document.original_name}
        )

        db.session.commit()

        return send_file(
            path,
            as_attachment=True,
            download_name=document.original_name
        )


    # ---------------- EDIT DOCUMENT ----------------

    @app.route(
        "/documents/<int:document_id>/edit",
        methods=["GET", "POST"]
    )
    @document_access_required("edit")
    def edit_document(document_id, document):

        form = RenameForm(
            data={
                "name": document.original_name,
                "category": document.category
            }
        )

        if form.validate_on_submit():

            old = {
                "name": document.original_name,
                "category": document.category
            }

            document.original_name = (
                secure_filename(form.name.data)
                or document.original_name
            )

            document.category = form.category.data.strip()

            document.updated_at = utcnow()

            log_event(
                "DOCUMENT_EDIT",
                document_id=document.id,
                detail={
                    "before": old,
                    "after": {
                        "name": document.original_name,
                        "category": document.category
                    }
                }
            )

            db.session.commit()

            flash(
                "Document details updated.",
                "success"
            )

            return redirect(url_for("dashboard"))

        return render_template(
            "edit.html",
            document=document,
            form=form
        )


    # ---------------- DELETE DOCUMENT ----------------

    @app.post("/documents/<int:document_id>/delete")
    @login_required
    def delete_document(document_id):

        document = db.session.get(Document, document_id)

        if (
            not document
            or (
                current_user.role != "admin"
                and document.owner_id != current_user.id
            )
        ):

            log_event(
                "DENIED_DOCUMENT_DELETE",
                document_id=document_id,
                detail={"path": request.path}
            )

            db.session.commit()
            abort(404)

        path = (
            Path(current_app.config["UPLOAD_FOLDER"])
            / document.stored_name
        )

        log_event(
            "DELETE",
            document_id=document.id,
            detail={"filename": document.original_name}
        )

        Grant.query.filter_by(
            document_id=document.id
        ).delete()

        db.session.delete(document)
        db.session.commit()

        if path.exists():
            path.unlink()

        flash(
            "Document deleted.",
            "success"
        )

        return redirect(url_for("dashboard"))
    # ---------------- PERMISSIONS ----------------

    @app.route(
        "/documents/<int:document_id>/permissions",
        methods=["GET", "POST"]
    )
    @login_required
    def permissions(document_id):

        document = db.session.get(
            Document,
            document_id
        )

        if (
            not document
            or (
                current_user.role != "admin"
                and document.owner_id != current_user.id
            )
        ):

            log_event(
                "DENIED_PERMISSION_MANAGEMENT",
                document_id=document_id
            )

            db.session.commit()
            abort(404)

        form = GrantForm()

        if form.validate_on_submit():

            target = User.query.filter_by(
                email=form.email.data.strip().lower()
            ).first()

            if not target:

                flash(
                    "No user found with that email.",
                    "error"
                )

            elif target.id == document.owner_id:

                flash(
                    "The owner already has full control.",
                    "error"
                )

            else:

                grant = Grant.query.filter_by(
                    document_id=document.id,
                    user_id=target.id
                ).first()

                old = grant.permission if grant else None

                if grant:

                    grant.permission = form.permission.data

                else:

                    db.session.add(
                        Grant(
                            document_id=document.id,
                            user_id=target.id,
                            permission=form.permission.data
                        )
                    )

                log_event(
                    "PERMISSION_GRANT"
                    if old is None
                    else "PERMISSION_CHANGE",
                    document_id=document.id,
                    target_user_id=target.id,
                    detail={
                        "old": old,
                        "new": form.permission.data
                    }
                )

                db.session.commit()

                flash(
                    "Permission saved.",
                    "success"
                )

                return redirect(
                    url_for(
                        "permissions",
                        document_id=document.id
                    )
                )

        grants = Grant.query.filter_by(
            document_id=document.id
        ).all()

        return render_template(
            "permissions.html",
            document=document,
            grants=grants,
            form=form
        )


    # ---------------- REVOKE PERMISSION ----------------

    @app.post(
        "/documents/<int:document_id>/permissions/<int:grant_id>/revoke"
    )
    @login_required
    def revoke_permission(document_id, grant_id):

        document = db.session.get(
            Document,
            document_id
        )

        if (
            not document
            or (
                current_user.role != "admin"
                and document.owner_id != current_user.id
            )
        ):

            log_event(
                "DENIED_PERMISSION_REVOKE",
                document_id=document_id
            )

            db.session.commit()
            abort(404)

        grant = Grant.query.filter_by(
            id=grant_id,
            document_id=document.id
        ).first_or_404()

        target_id = grant.user_id
        old_permission = grant.permission

        db.session.delete(grant)

        log_event(
            "PERMISSION_REVOKE",
            document_id=document.id,
            target_user_id=target_id,
            detail={"old": old_permission}
        )

        db.session.commit()

        flash(
            "Access revoked immediately.",
            "success"
        )

        return redirect(
            url_for(
                "permissions",
                document_id=document.id
            )
        )


    # ---------------- ADMIN ACTIVITY ----------------

    @app.route("/admin/activity")
    @admin_required
    def admin_activity():

        events = AuditEvent.query.order_by(
            AuditEvent.id.desc()
        ).limit(300).all()

        audit_status = verify_audit_chain_details()

        return render_template(
            "activity.html",
            events=events,
            chain_valid=audit_status["valid"],
            audit_status=audit_status
        )


    # ---------------- ADMIN USERS ----------------

    @app.route("/admin/users")
    @admin_required
    def admin_users():

        users = User.query.order_by(
            User.id.asc()
        ).all()

        return render_template(
            "users.html",
            users=users
        )


    # ---------------- TOGGLE USER ----------------

    @app.route(
        "/admin/users/<int:user_id>/toggle",
        methods=["POST"]
    )
    @admin_required
    def toggle_user(user_id):

        user = db.session.get(
            User,
            user_id
        )

        if not user or user.id == current_user.id:
            abort(404)

        user.is_active_account = not user.is_active_account

        log_event(
            "USER_DISABLED"
            if not user.is_active_account
            else "USER_ENABLED",
            target_user_id=user.id
        )

        db.session.commit()

        return redirect(url_for("admin_users"))


    # ---------------- AUDIT VERIFICATION ROUTE ----------------

    @app.route("/admin/audit/verify")
    @admin_required
    def audit_verify():

        audit_status = verify_audit_chain_details()

        return {
            "audit_chain_valid": audit_status["valid"],
            "audit_details": audit_status
        }


    # ---------------- DATABASE ----------------

    with app.app_context():
        db.create_all()

    return app


# ---------------- START APPLICATION ----------------

app = create_app()


if __name__ == "__main__":

    production = (
        os.environ.get("APP_ENV", "development").lower()
        == "production"
    )

    app.run(
        debug=not production
    )