from conftest import login
from app import db, Grant, AuditEvent
from pathlib import Path


def test_ungranted_viewer_cannot_download_other_users_document(client, app):
    login(client, "viewer@example.com", "ViewerPass!123")
    response = client.get(f"/documents/{app.config['TEST_DOC_ID']}/download")
    assert response.status_code == 404


def test_other_owner_cannot_access_document(client, app):
    login(client, "two@example.com", "OwnerPass!123")
    response = client.get(f"/documents/{app.config['TEST_DOC_ID']}/download")
    assert response.status_code == 404


def test_granted_viewer_can_download_but_revocation_blocks_next_request(client, app):
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    (Path(app.config["UPLOAD_FOLDER"]) / "private-test").write_bytes(
        b"private test content"
    )

    with app.app_context():
        db.session.add(
            Grant(
                document_id=app.config["TEST_DOC_ID"],
                user_id=app.config["TEST_VIEWER_ID"],
                permission="read"
            )
        )
        db.session.commit()

    login(client, "viewer@example.com", "ViewerPass!123")

    response = client.get(f"/documents/{app.config['TEST_DOC_ID']}/download")
    assert response.status_code == 200

    with app.app_context():
        grant = Grant.query.filter_by(
            document_id=app.config["TEST_DOC_ID"],
            user_id=app.config["TEST_VIEWER_ID"]
        ).first()

        db.session.delete(grant)
        db.session.commit()

    response = client.get(f"/documents/{app.config['TEST_DOC_ID']}/download")
    assert response.status_code == 404


def test_viewer_cannot_open_edit_route(client, app):
    login(client, "viewer@example.com", "ViewerPass!123")
    response = client.get(f"/documents/{app.config['TEST_DOC_ID']}/edit")
    assert response.status_code == 404