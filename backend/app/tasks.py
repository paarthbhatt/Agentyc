import uuid
from sqlalchemy import func
from app.worker import celery_app
from app.db.session import SessionLocal
from app.models import Agent, TelemetryEvent, BehaviorBaseline

@celery_app.task
def recalculate_agent_baseline(agent_id: str) -> dict:
    """
    Recalculates the behavior baseline for a given agent by analyzing its recent telemetry.
    """
    db = SessionLocal()
    try:
        agent_uuid = uuid.UUID(agent_id)
        agent = db.query(Agent).filter(Agent.id == agent_uuid).one_or_none()
        if not agent:
            return {"status": "skipped", "reason": "Agent not found"}

        # Get all telemetry events for this agent
        events = db.query(TelemetryEvent).filter(TelemetryEvent.agent_id == agent_uuid).all()
        
        if not events:
            return {"status": "skipped", "reason": "No events found"}

        event_count = len(events)
        
        # Calculate frequencies
        tool_freq = {}
        action_freq = {}
        resource_freq = {}
        anomaly_count = 0
        last_score = 0
        
        for e in events:
            if e.event_type == "policy.violation":
                anomaly_count += 1
            last_score = e.risk_score
                
            payload = e.payload
            if not isinstance(payload, dict):
                continue
                
            t_name = payload.get("tool_name")
            a_name = payload.get("action")
            r_name = payload.get("resource")
            
            if t_name: tool_freq[t_name] = tool_freq.get(t_name, 0) + 1
            if a_name: action_freq[a_name] = action_freq.get(a_name, 0) + 1
            if r_name: resource_freq[r_name] = resource_freq.get(r_name, 0) + 1
            
        # Top 5 normal items
        normal_tools = [k for k, v in sorted(tool_freq.items(), key=lambda item: item[1], reverse=True)[:5]]
        normal_actions = [k for k, v in sorted(action_freq.items(), key=lambda item: item[1], reverse=True)[:5]]
        normal_resources = [k for k, v in sorted(resource_freq.items(), key=lambda item: item[1], reverse=True)[:5]]

        # Update or create baseline
        baseline = db.query(BehaviorBaseline).filter(BehaviorBaseline.agent_id == agent_uuid).first()
        if not baseline:
            baseline = BehaviorBaseline(agent_id=agent_uuid)
            db.add(baseline)
            
        baseline.normal_tools = normal_tools
        baseline.normal_actions = normal_actions
        baseline.normal_resources = normal_resources
        baseline.event_count = event_count
        baseline.anomaly_count = anomaly_count
        baseline.last_score = last_score

        db.commit()
        
        return {
            "status": "success", 
            "agent_id": agent_id, 
            "events_processed": event_count,
            "anomaly_count": anomaly_count
        }
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


@celery_app.task
def index_telemetry_opensearch(event_id: str) -> dict:
    """Async index telemetry to OpenSearch."""
    from opensearchpy import OpenSearch
    db = SessionLocal()
    try:
        event = db.query(TelemetryEvent).filter(TelemetryEvent.id == event_id).one_or_none()
        if not event:
            return {"status": "skipped"}
            
        client = OpenSearch(
            hosts=[{"host": "opensearch", "port": 9200}],
            http_auth=("admin", "ChangeMeBeforeUse123!"),
            use_ssl=False
        )
        
        doc = {
            "id": str(event.id),
            "agent_id": str(event.agent_id),
            "event_type": event.event_type,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "trust_score": event.trust_score,
            "payload": event.payload,
            "occurred_at": event.occurred_at.isoformat()
        }
        
        client.index(
            index="telemetry-events",
            body=doc,
            id=str(event.id),
            refresh=True
        )
        return {"status": "success"}
    except Exception as e:
        print(f"OpenSearch index failed: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


@celery_app.task
def sync_graph_neo4j(agent_id: str) -> dict:
    """Async sync agent info to Neo4j graph."""
    from neo4j import GraphDatabase
    import os
    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
        if not agent:
            return {"status": "skipped"}
            
        auth_str = os.getenv("NEO4J_AUTH", "neo4j/changeme")
        user, pwd = auth_str.split("/")
        driver = GraphDatabase.driver("bolt://neo4j:7687", auth=(user, pwd))
        
        with driver.session() as session:
            session.run(
                "MERGE (a:Agent {id: $id}) "
                "SET a.name = $name, a.role = $role, a.risk_score = $risk",
                id=str(agent.id), name=agent.name, role=agent.role, risk=agent.risk_score
            )
            
        return {"status": "success"}
    except Exception as e:
        print(f"Neo4j sync failed: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


@celery_app.task
def sync_event_neo4j(event_id: str) -> dict:
    """Async sync telemetry event to Neo4j graph."""
    from neo4j import GraphDatabase
    import os
    db = SessionLocal()
    try:
        event = db.query(TelemetryEvent).filter(TelemetryEvent.id == event_id).one_or_none()
        if not event:
            return {"status": "skipped"}
            
        auth_str = os.getenv("NEO4J_AUTH", "neo4j/changeme")
        user, pwd = auth_str.split("/")
        driver = GraphDatabase.driver("bolt://neo4j:7687", auth=(user, pwd))
        
        with driver.session() as session:
            # 1. Create Event node and link to Agent
            session.run(
                "MERGE (a:Agent {id: $agent_id}) "
                "MERGE (e:Event {id: $event_id}) "
                "SET e.type = $type, e.risk = $risk "
                "MERGE (a)-[:EMITTED]->(e)",
                agent_id=str(event.agent_id),
                event_id=str(event.id),
                type=event.event_type,
                risk=event.risk_score
            )
            
            payload = event.payload or {}
            tool_name = payload.get("tool_name")
            resource = payload.get("resource")
            
            # 2. Link Tool if present
            if tool_name:
                session.run(
                    "MERGE (a:Agent {id: $agent_id}) "
                    "MERGE (t:Tool {name: $tool_name}) "
                    "MERGE (a)-[:USED_TOOL {event_id: $event_id}]->(t)",
                    agent_id=str(event.agent_id),
                    tool_name=tool_name,
                    event_id=str(event.id)
                )
                
            # 3. Link Resource if present
            if resource:
                source_id = str(event.agent_id)
                source_label = "Agent"
                source_key = "id"
                if tool_name:
                    source_id = tool_name
                    source_label = "Tool"
                    source_key = "name"
                
                session.run(
                    f"MERGE (s:{source_label} {{{source_key}: $source_id}}) "
                    "MERGE (r:Resource {name: $resource}) "
                    "MERGE (s)-[:ACCESSED_RESOURCE {{event_id: $event_id}}]->(r)",
                    source_id=source_id,
                    resource=resource,
                    event_id=str(event.id)
                )
            
        return {"status": "success"}
    except Exception as e:
        print(f"Neo4j event sync failed: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


@celery_app.task
def sync_incident_neo4j(incident_id: str) -> dict:
    """Async sync incident to Neo4j graph."""
    from neo4j import GraphDatabase
    import os
    from app.models import Incident
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).one_or_none()
        if not incident:
            return {"status": "skipped"}
            
        auth_str = os.getenv("NEO4J_AUTH", "neo4j/changeme")
        user, pwd = auth_str.split("/")
        driver = GraphDatabase.driver("bolt://neo4j:7687", auth=(user, pwd))
        
        with driver.session() as session:
            session.run(
                "MERGE (a:Agent {id: $agent_id}) "
                "MERGE (i:Incident {id: $incident_id}) "
                "SET i.title = $title, i.category = $category, i.status = $status "
                "MERGE (a)-[:TRIGGERED_INCIDENT]->(i)",
                agent_id=str(incident.agent_id),
                incident_id=str(incident.id),
                title=incident.title,
                category=incident.category,
                status=incident.status
            )
            
        return {"status": "success"}
    except Exception as e:
        print(f"Neo4j incident sync failed: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


@celery_app.task
def index_incident_opensearch(incident_id: str) -> dict:
    """Async index incident to OpenSearch."""
    from opensearchpy import OpenSearch
    from app.models import Incident
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).one_or_none()
        if not incident:
            return {"status": "skipped"}
            
        client = OpenSearch(
            hosts=[{"host": "opensearch", "port": 9200}],
            http_auth=("admin", "ChangeMeBeforeUse123!"),
            use_ssl=False
        )
        
        doc = {
            "id": str(incident.id),
            "agent_id": str(incident.agent_id),
            "session_id": incident.session_id,
            "title": incident.title,
            "category": incident.category,
            "severity": incident.severity,
            "status": incident.status,
            "root_cause": incident.root_cause,
            "evidence": incident.evidence,
            "response_actions": incident.response_actions,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat()
        }
        
        client.index(
            index="incidents",
            body=doc,
            id=str(incident.id),
            refresh=True
        )
        return {"status": "success"}
    except Exception as e:
        print(f"OpenSearch incident index failed: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()
