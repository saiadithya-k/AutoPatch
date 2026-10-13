"""Read models derived exclusively from persisted workflow evidence."""
import json
from backend.database.models import WorkflowModel, VulnerabilityModel, PatchAttemptModel, ValidationResultModel, ReviewDecisionModel, AuditEventModel


def decoded(value, expected, field, errors, record_id, element_type=None):
    """Keep readable history when a stored JSON field is corrupt."""
    try:
        result = json.loads(value) if value else expected()
        if not isinstance(result, expected):
            raise ValueError(f"Expected {expected.__name__}")
        if element_type and any(not isinstance(item, element_type) for item in result):
            raise ValueError("Invalid list item type")
        return result
    except (ValueError, TypeError):
        errors.append({"record_id": record_id, "field": field, "error": "Stored evidence is malformed or has the wrong type"})
        return expected()


def latest_candidates(patches):
    latest = {}
    for proposal in patches:
        current = latest.get(proposal.vulnerability_id)
        if current is None or (proposal.created_at, proposal.id) > (current.created_at, current.id):
            latest[proposal.vulnerability_id] = proposal
    return latest


def row_data(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


def workflow_data(row):
    data = row_data(row)
    errors = []
    data["errors"] = decoded(data.pop("errors_json"), list, "errors_json", errors, row.id, str)
    data["scan_metadata"] = decoded(data["scan_metadata"], dict, "scan_metadata", errors, row.id)
    data["evidence_errors"] = errors
    data.pop("request_json", None)
    return data


def patch_data(db, row):
    data = row_data(row)
    errors = []
    data["files_changed"] = decoded(row.files_changed, list, "files_changed", errors, row.id, str)
    data["retry_decision"] = decoded(row.retry_decision, dict, "retry_decision", errors, row.id) if row.retry_decision else None
    data["evidence_errors"] = errors
    review = db.query(ReviewDecisionModel).filter_by(patch_attempt_id=row.id).first()
    data["review"] = row_data(review) if review else None
    return data


def workflow_report(db, workflow):
    findings = db.query(VulnerabilityModel).filter_by(workflow_id=workflow.id).order_by(VulnerabilityModel.risk_score.desc()).all()
    patches = db.query(PatchAttemptModel).filter_by(workflow_id=workflow.id).order_by(PatchAttemptModel.created_at).all()
    patch_ids = [p.id for p in patches]
    validations = db.query(ValidationResultModel).filter(ValidationResultModel.patch_attempt_id.in_(patch_ids)).all()
    reviews = db.query(ReviewDecisionModel).filter(ReviewDecisionModel.patch_attempt_id.in_(patch_ids)).all()
    audits = db.query(AuditEventModel).filter_by(workflow_id=workflow.id).order_by(AuditEventModel.created_at).all()
    reviewable = {p.vulnerability_id for p in latest_candidates(patches).values() if p.status in {"READY_FOR_REVIEW", "VALIDATED", "APPROVED"}}
    evidence_errors = []
    validation_data = []
    for v in validations:
        data = row_data(v)
        errors = []
        data["scanner_metadata"] = decoded(data["scanner_metadata"], dict, "scanner_metadata", errors, v.id)
        data["new_findings"] = decoded(data["new_findings"], list, "new_findings", errors, v.id)
        data["evidence_errors"] = errors
        evidence_errors.extend(errors)
        validation_data.append(data)
    audit_data = []
    for a in audits:
        data = row_data(a)
        errors = []
        data["metadata"] = decoded(data.pop("metadata_json"), dict, "metadata_json", errors, a.id)
        data["evidence_errors"] = errors
        evidence_errors.extend(errors)
        audit_data.append(data)
    wf_data = workflow_data(workflow)
    proposals = [patch_data(db, p) for p in patches]
    evidence_errors.extend(wf_data["evidence_errors"])
    for p in proposals:
        evidence_errors.extend(p["evidence_errors"])
    return {"workflow": wf_data, "findings": [row_data(f) for f in findings], "patches": proposals, "validations": validation_data, "reviews": [row_data(r) for r in reviews], "audit_events": audit_data, "unresolved_findings": [f.id for f in findings if f.id not in reviewable], "evidence_errors": evidence_errors}
