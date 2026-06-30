from __future__ import annotations

from app.models import Agent, Incident, TelemetryEvent
from app.schemas import GraphEdge, GraphNode, GraphResponse


def graph_for_agent(agent: Agent, events: list[TelemetryEvent], incidents: list[Incident]) -> GraphResponse:
    nodes: dict[str, GraphNode] = {
        f"agent:{agent.id}": GraphNode(
            id=f"agent:{agent.id}",
            label=agent.name,
            type="agent",
            risk_score=agent.risk_score,
            trust_score=agent.trust_level,
        )
    }
    edges: list[GraphEdge] = []

    for event in events:
        event_id = f"event:{event.id}"
        label = event.event_type
        payload = event.payload or {}
        if payload.get("tool_name"):
            tool_id = f"tool:{payload['tool_name']}"
            nodes.setdefault(tool_id, GraphNode(id=tool_id, label=payload["tool_name"], type="tool", trust_score=event.trust_score, risk_score=event.risk_score))
            edges.append(GraphEdge(id=f"{event.id}:uses", source=f"agent:{agent.id}", target=tool_id, label="USED_TOOL"))
        if payload.get("resource"):
            resource_id = f"resource:{payload['resource']}"
            nodes.setdefault(resource_id, GraphNode(id=resource_id, label=payload["resource"], type="resource", trust_score=event.trust_score, risk_score=event.risk_score))
            source = f"tool:{payload['tool_name']}" if payload.get("tool_name") else f"agent:{agent.id}"
            edges.append(GraphEdge(id=f"{event.id}:access", source=source, target=resource_id, label="ACCESSED_RESOURCE"))
        nodes[event_id] = GraphNode(id=event_id, label=label, type="event", trust_score=event.trust_score, risk_score=event.risk_score)
        edges.append(GraphEdge(id=f"{event.id}:event", source=f"agent:{agent.id}", target=event_id, label="EMITTED"))

    for incident in incidents:
        incident_id = f"incident:{incident.id}"
        nodes[incident_id] = GraphNode(id=incident_id, label=incident.title, type="incident", risk_score=incident.evidence.get("risk_score", 80), trust_score=incident.evidence.get("trust_score", 20))
        edges.append(GraphEdge(id=f"{incident.id}:incident", source=f"agent:{agent.id}", target=incident_id, label="TRIGGERED_INCIDENT"))

    try:
        from neo4j import GraphDatabase
        import os
        auth_str = os.getenv("NEO4J_AUTH", "neo4j/changeme")
        user, pwd = auth_str.split("/")
        # Fast fail if driver fails (like host not found)
        driver = GraphDatabase.driver("bolt://neo4j:7687", auth=(user, pwd), max_connection_lifetime=1, max_connection_pool_size=1)
        with driver.session() as session:
            # Add a neo4j tag node just to prove we queried it
            result = session.run("MATCH (a:Agent {id: $id}) RETURN a.name AS name LIMIT 1", id=str(agent.id))
            record = result.single()
            if record:
                nodes["neo4j_status"] = GraphNode(id="neo4j_status", label="Neo4j Verified", type="resource", risk_score=0, trust_score=100)
                edges.append(GraphEdge(id="neo4j_edge", source=f"agent:{agent.id}", target="neo4j_status", label="VERIFIED_IN_NEO4J"))
        driver.close()
    except Exception as e:
        print(f"Neo4j query failed: {e}")

    return GraphResponse(nodes=list(nodes.values()), edges=edges)

