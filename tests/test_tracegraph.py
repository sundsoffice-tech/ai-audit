"""Tests for Multi-Agent Trace-Graphs (DAG)."""

from ai_audit.tracegraph import TraceGraph


def test_single_node_graph() -> None:
    """Graph with one root node."""
    g = TraceGraph(trace_id="t1", tenant_id="acme")
    root = g.add_node(agent_id="orchestrator", action="plan")
    assert g.node_count == 1
    assert len(g.roots) == 1
    assert g.depth == 1
    assert root.node_hash != ""


def test_delegation_pattern() -> None:
    """Orchestrator delegates to two specialists."""
    g = TraceGraph(trace_id="t1")
    root = g.add_node(agent_id="orchestrator", action="plan")
    g.add_node(agent_id="researcher", action="search", parent_id=root.node_id)
    g.add_node(agent_id="writer", action="draft", parent_id=root.node_id)

    assert g.node_count == 3
    assert g.depth == 2
    children = g.get_children(root.node_id)
    assert len(children) == 2


def test_deep_chain() -> None:
    """Chain: orchestrator → researcher → fact-checker → reviewer."""
    g = TraceGraph(trace_id="t1")
    n0 = g.add_node(agent_id="orchestrator", action="plan")
    n1 = g.add_node(agent_id="researcher", action="search", parent_id=n0.node_id)
    n2 = g.add_node(agent_id="fact-checker", action="verify", parent_id=n1.node_id)
    g.add_node(agent_id="reviewer", action="review", parent_id=n2.node_id)

    assert g.depth == 4


def test_parallel_pattern() -> None:
    """Orchestrator spawns 3 parallel workers."""
    g = TraceGraph(trace_id="t1")
    root = g.add_node(agent_id="orchestrator", action="parallel")
    for i in range(3):
        g.add_node(
            agent_id=f"worker-{i}", action="execute",
            parent_id=root.node_id,
            delegation_reason=f"Subtask {i}",
        )

    assert g.node_count == 4
    assert len(g.get_children(root.node_id)) == 3
    assert g.depth == 2


def test_integrity_verification() -> None:
    """Untampered graph should pass integrity check."""
    g = TraceGraph(trace_id="t1")
    root = g.add_node(agent_id="a1", action="plan")
    g.add_node(agent_id="a2", action="execute", parent_id=root.node_id)
    assert g.verify_integrity()


def test_tampered_node_detected() -> None:
    """Modifying a node after creation should fail integrity check."""
    g = TraceGraph(trace_id="t1")
    root = g.add_node(agent_id="a1", action="plan")
    root.agent_id = "TAMPERED"
    assert not g.verify_integrity()


def test_no_cycles() -> None:
    """Well-formed DAG should have no cycles."""
    g = TraceGraph(trace_id="t1")
    root = g.add_node(agent_id="a1", action="plan")
    g.add_node(agent_id="a2", action="execute", parent_id=root.node_id)
    assert not g.has_cycles()


def test_agent_lineage() -> None:
    """Lineage should trace from leaf back to root."""
    g = TraceGraph(trace_id="t1")
    n0 = g.add_node(agent_id="orchestrator", action="plan")
    n1 = g.add_node(agent_id="researcher", action="search", parent_id=n0.node_id)
    n2 = g.add_node(agent_id="writer", action="draft", parent_id=n1.node_id)

    lineage = g.get_agent_lineage(n2.node_id)
    assert len(lineage) == 3
    assert lineage[0].agent_id == "orchestrator"
    assert lineage[1].agent_id == "researcher"
    assert lineage[2].agent_id == "writer"


def test_to_dict_serialization() -> None:
    """Graph should serialize to a dict."""
    g = TraceGraph(trace_id="t1", tenant_id="acme")
    root = g.add_node(agent_id="a1", action="plan")
    g.add_node(agent_id="a2", action="execute", parent_id=root.node_id)

    d = g.to_dict()
    assert d["trace_id"] == "t1"
    assert d["tenant_id"] == "acme"
    assert d["node_count"] == 2
    assert len(d["nodes"]) == 2  # type: ignore[arg-type]


def test_input_output_hashing() -> None:
    """Input/output data should be hashed, not stored."""
    g = TraceGraph(trace_id="t1")
    node = g.add_node(
        agent_id="a1", action="execute",
        input_data="sensitive user query",
        output_data="sensitive response",
    )
    assert node.input_hash != ""
    assert node.output_hash != ""
    # Original data not stored in the node
    assert "sensitive" not in node.input_hash


def test_multiple_roots() -> None:
    """Graph can have multiple root nodes (concurrent workflows)."""
    g = TraceGraph(trace_id="t1")
    g.add_node(agent_id="workflow-a", action="start")
    g.add_node(agent_id="workflow-b", action="start")
    assert len(g.roots) == 2
    assert g.node_count == 2
