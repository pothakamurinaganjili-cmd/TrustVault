from conftest import login
from app import db, Document


def test_owner_can_delete_own_document(app, client):
    document_id = app.config["TEST_DOC_ID"]

    login(client, "one@example.com", "OwnerPass!123")

    response = client.post(
        f"/documents/{document_id}/delete"
    )

    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(Document, document_id) is None


def test_admin_can_delete_document(app, client):
    document_id = app.config["TEST_DOC_ID"]

    login(client, "admin@example.com", "AdminPass!123")

    response = client.post(
        f"/documents/{document_id}/delete"
    )

    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(Document, document_id) is None


def test_viewer_cannot_delete_document(app, client):
    document_id = app.config["TEST_DOC_ID"]

    login(client, "viewer@example.com", "ViewerPass!123")

    response = client.post(
        f"/documents/{document_id}/delete"
    )

    assert response.status_code == 404

    with app.app_context():
        assert db.session.get(Document, document_id) is not None


def test_other_owner_cannot_delete_document(app, client):
    document_id = app.config["TEST_DOC_ID"]

    login(client, "two@example.com", "OwnerPass!123")

    response = client.post(
        f"/documents/{document_id}/delete"
    )

    assert response.status_code == 404

    with app.app_context():
        assert db.session.get(Document, document_id) is not None