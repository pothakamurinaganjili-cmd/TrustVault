import pytest
from app import create_app, db, User, Document, Grant

@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(tmp_path / "test.db"),
        "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        "AUDIT_CHECKPOINT_FILE": str(tmp_path / "audit_checkpoint.json"),
        "SECRET_KEY": "test-secret",
        "AUDIT_HMAC_KEY": "test-audit-key",
    })
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(name="Admin", email="admin@example.com", role="admin"); admin.set_password("AdminPass!123")
        owner1 = User(name="Owner One", email="one@example.com", role="owner"); owner1.set_password("OwnerPass!123")
        owner2 = User(name="Owner Two", email="two@example.com", role="owner"); owner2.set_password("OwnerPass!123")
        viewer = User(name="Viewer", email="viewer@example.com", role="viewer"); viewer.set_password("ViewerPass!123")
        db.session.add_all([admin, owner1, owner2, viewer]); db.session.commit()
        doc = Document(original_name="private.pdf", stored_name="private-test", category="Legal", owner_id=owner1.id)
        db.session.add(doc); db.session.commit()
        app.config["TEST_DOC_ID"] = doc.id
        app.config["TEST_OWNER_ID"] = owner1.id
        app.config["TEST_OTHER_OWNER_ID"] = owner2.id
        app.config["TEST_VIEWER_ID"] = viewer.id
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def login(client, email, password):
    response = client.post(
        "/login",
        data={
            "email": email,
            "password": password
        },
        follow_redirects=True
    )

    print("\nLOGIN RESPONSE:")
    print(response.get_data(as_text=True))

    return response