# main.py — Hushh Vault Backend
# Run: python -m uvicorn main:app --reload --port 3001

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import SQLModel, Field, Session, create_engine, select
from typing import Optional
from datetime import datetime
import random
import string

# ── App Setup ─────────────────────────────────────────

app = FastAPI(title="Hushh Vault API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = create_engine("sqlite:///vault.db", echo=False)

# ── Models ───────────────────────────────────────────

class Member(SQLModel, table=True):
    id: str = Field(primary_key=True)
    name: str
    email: str
    level: int
    status: str
    joined: str


class AuditEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: str
    type: str
    actor: str
    resource: str
    hash: str


SQLModel.metadata.create_all(engine)

# ── Helpers ──────────────────────────────────────────

def rand_hash() -> str:
    chars = string.ascii_lowercase + string.digits
    a = ''.join(random.choices(chars, k=6))
    b = ''.join(random.choices(chars, k=6))
    return f"{a}...{b}"


def log_audit(event_type: str, actor: str, resource: str):
    ts = datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")
    event = AuditEvent(
        timestamp=ts,
        type=event_type,
        actor=actor,
        resource=resource,
        hash=rand_hash()
    )
    with Session(engine) as s:
        s.add(event)
        s.commit()

# ── Members APIs ─────────────────────────────────────

@app.get("/api/members")
def get_members():
    with Session(engine) as s:
        return s.exec(select(Member)).all()


@app.post("/api/members")
def add_member(m: Member):
    with Session(engine) as s:
        existing = s.get(Member, m.id)
        if existing:
            raise HTTPException(status_code=409, detail="Member ID already exists")
        s.add(m)
        s.commit()

    log_audit("add", "ADMIN", f"{m.id} - {m.name} registered at Level {m.level}")
    return {"success": True, "id": m.id}


@app.patch("/api/members/{member_id}/status")
def update_member_status(member_id: str, payload: dict):
    new_status = payload.get("status")

    if new_status not in ("active", "suspended"):
        raise HTTPException(status_code=400, detail="Status must be 'active' or 'suspended'")

    with Session(engine) as s:
        member = s.get(Member, member_id)
        if not member:
            raise HTTPException(status_code=404, detail="Member not found")

        member.status = new_status
        s.add(member)
        s.commit()

    event_type = "suspend" if new_status == "suspended" else "access"
    log_audit(event_type, "ADMIN", f"{member_id} status changed to {new_status}")

    return {"success": True}


@app.delete("/api/members/{member_id}")
def delete_member(member_id: str):
    with Session(engine) as s:
        member = s.get(Member, member_id)
        if not member:
            raise HTTPException(status_code=404, detail="Member not found")

        s.delete(member)
        s.commit()

    log_audit("change", "ADMIN", f"{member_id} permanently removed")
    return {"success": True}

# ── Audit APIs ───────────────────────────────────────

@app.get("/api/audit")
def get_audit():
    with Session(engine) as s:
        return s.exec(select(AuditEvent).order_by(AuditEvent.id.desc())).all()


@app.post("/api/audit")
def post_audit(payload: dict):
    event_type = payload.get("type", "change")
    actor = payload.get("actor", "ADMIN")
    resource = payload.get("resource", "")

    if not resource:
        raise HTTPException(status_code=400, detail="'resource' field is required")

    log_audit(event_type, actor, resource)
    return {"success": True}

# ── Health Check ─────────────────────────────────────

@app.get("/api/health")
def health():
    with Session(engine) as s:
        member_count = len(s.exec(select(Member)).all())
        audit_count = len(s.exec(select(AuditEvent)).all())

    return {
        "status": "ok",
        "members": member_count,
        "audit_events": audit_count,
        "vault": "ORG-7X92-NM"
    }