
"""Create or update TrustVault demo accounts.

For local development and testing only.
Do not run this demo seed script in production.
"""

from app import app, db, User


ACCOUNTS = [
    ("Demo Admin", "admin@example.com", "AdminDemo!2026", "admin"),
    ("Demo Owner", "owner@example.com", "OwnerDemo!2026", "owner"),
    ("Demo Viewer", "viewer@example.com", "ViewerDemo!2026", "viewer"),
]


def create_demo_accounts():

    with app.app_context():

        # Create database tables if they do not exist
        db.create_all()

        for name, email, password, role in ACCOUNTS:

            # Check whether the account already exists
            user = User.query.filter_by(email=email).first()

            # Create a new account if it does not exist
            if not user:

                user = User(
                    name=name,
                    email=email,
                    role=role
                )

                db.session.add(user)

            # Update account details and reset demo password
            user.name = name
            user.role = role
            user.is_active_account = True
            user.set_password(password)

        # Save all changes
        db.session.commit()

        print("Demo accounts created/updated successfully.")


if __name__ == "__main__":
    create_demo_accounts()
