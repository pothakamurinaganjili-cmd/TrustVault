from app import db, log_event, verify_audit_chain, AuditEvent

def test_audit_chain_verifies(app):
    with app.app_context():
        log_event("TEST_EVENT", detail={"example": "value"})
        db.session.commit()
        assert verify_audit_chain() is True

def test_audit_chain_detects_tampering(app):
    with app.app_context():
        log_event("TEST_EVENT", detail={"example": "value"})
        db.session.commit()
        event = AuditEvent.query.first()
        event.detail = '{"changed":true}'
        db.session.commit()
        assert verify_audit_chain() is False
