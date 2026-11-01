"""Create demo accounts. Change these passwords before deployment."""
from app import app, db, User

ACCOUNTS = [
    ("Demo Admin", "admin@trustvault.local", "AdminDemo!2026", "admin"),
    ("Demo Owner", "owner@trustvault.local", "OwnerDemo!2026", "owner"),
    ("Demo Viewer", "viewer@trustvault.local", "ViewerDemo!2026", "viewer"),
]

with app.app_context():
    db.create_all()
    for name, email, password, role in ACCOUNTS:
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=name, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
    db.session.commit()
    print("Demo accounts ready. Change all passwords before deployment.")
