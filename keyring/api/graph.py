from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from keyring.api.deps import CurrentSession, get_current_session, get_db
from keyring.core.errors import NotFoundError
from keyring.models.keys import Kek, SubjectKey

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("")
def get_graph(db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    keks = db.execute(select(Kek)).scalars().all()
    sks = db.execute(select(SubjectKey)).scalars().all()

    nodes = []
    edges = []
    for kek in keks:
        dependents = sum(1 for sk in sks if sk.kek_id == kek.id)
        nodes.append({"id": kek.id, "type": "kek", "state": kek.state, "dependentCount": dependents, "parentId": None})
    for sk in sks:
        # Item clusters aggregated on the subject-key node — never one node per DEK.
        nodes.append({"id": sk.id, "type": "subject_key", "state": sk.state, "dependentCount": sk.record_count, "parentId": sk.kek_id})
        edges.append({"source": sk.kek_id, "target": sk.id})

    return {"nodes": nodes, "edges": edges}


@router.get("/{node_id}/downstream")
def downstream(node_id: str, db: DbSession = Depends(get_db), current: CurrentSession = Depends(get_current_session)):
    kek = db.get(Kek, node_id)
    if kek is not None:
        ids = db.execute(select(SubjectKey.id).where(SubjectKey.kek_id == kek.id)).scalars().all()
        return {"descendantIds": ids}
    sk = db.get(SubjectKey, node_id)
    if sk is not None:
        return {"descendantIds": []}
    raise NotFoundError(target="node")
