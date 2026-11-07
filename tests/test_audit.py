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
def test_audit_chain_detects_middle_event_deletion(app):
    with app.app_context():
        log_event("FIRST_EVENT")
        log_event("SECOND_EVENT")
        log_event("THIRD_EVENT")
        db.session.commit()

        events = AuditEvent.query.order_by(
            AuditEvent.id.asc()
        ).all()

        db.session.delete(events[1])
        db.session.commit()

        assert verify_audit_chain() is False
def test_audit_chain_detects_event_reordering(app):
    from sqlalchemy import text

    with app.app_context():
        log_event("FIRST_EVENT")
        log_event("SECOND_EVENT")
        log_event("THIRD_EVENT")
        db.session.commit()

        events = AuditEvent.query.order_by(
            AuditEvent.id.asc()
        ).all()

        first_id = events[0].id
        second_id = events[1].id

        # Move first event to a temporary ID
        db.session.execute(
            text("UPDATE audit_event SET id = -100 WHERE id = :old"),
            {"old": first_id}
        )

        # Move second event into first event's position
        db.session.execute(
            text("UPDATE audit_event SET id = :new WHERE id = :old"),
            {"new": first_id, "old": second_id}
        )

        # Move first event into second event's position
        db.session.execute(
            text("UPDATE audit_event SET id = :new WHERE id = -100"),
            {"new": second_id}
        )

        db.session.commit()
        db.session.expire_all()

        assert verify_audit_chain() is False

def test_audit_chain_detects_last_event_deletion(app):
    with app.app_context():
        log_event("FIRST_EVENT")
        log_event("SECOND_EVENT")
        db.session.commit()

        last_event = AuditEvent.query.order_by(
            AuditEvent.id.desc()
        ).first()

        db.session.delete(last_event)
        db.session.commit()

        # Current implementation has no external final checkpoint.
        # Therefore, it does not detect deletion of the last event.
        assert verify_audit_chain() is False