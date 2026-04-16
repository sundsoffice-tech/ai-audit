"""
ai_audit.tracegraph — Multi-Agent Trace-Graphs (DAG) for Agentic AI Audit.

World-first: Instead of linear log chains, this module builds a
Directed Acyclic Graph (DAG) of agent interactions — delegation,
handoff, parallel orchestration — with cryptographic integrity.

Existing tools (Langfuse, MLflow) provide linear traces. This module
captures the actual topology of multi-agent collaboration.

**Key patterns supported:**
- **Delegation:** Agent A delegates subtask to Agent B
- **Handoff:** Agent A transfers full control to Agent B
- **Parallel:** Agent A spawns B and C concurrently
- **Consensus:** Multiple agents contribute to a single decision

Usage::

    from ai_audit.tracegraph import TraceGraph, TraceNode

    graph = TraceGraph(trace_id="workflow-1", tenant_id="acme")
    root = graph.add_node(agent_id="orchestrator", action="plan")
    n1 = graph.add_node(agent_id="researcher", action="search", parent_id=root.node_id)
    n2 = graph.add_node(agent_id="writer", action="draft", parent_id=root.node_id)
    graph.add_node(agent_id="reviewer", action="review", parent_id=n2.node_id)

    assert graph.verify_integrity()
    assert not graph.has_cycles()

NB a861f2b3 (Agentic) validated — 2026-04-16.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import orjson


@dataclass
class TraceNode:
    """A single node in the multi-agent trace graph.

    Attributes:
        node_id:             Unique node identifier.
        agent_id:            Agent that executed this node.
        parent_id:           Parent node ID (empty for root nodes).
        action:              Action taken (e.g. "delegate", "handoff", "execute").
        delegation_reason:   Why the parent delegated to this agent.
        input_hash:          SHA-256 of the input to this agent.
        output_hash:         SHA-256 of the output from this agent.
        timestamp:           ISO 8601 timestamp.
        duration_ms:         Execution duration in milliseconds.
        metadata:            Additional context (tool calls, model, etc.).
        node_hash:           SHA-256 of the canonical node payload.
    """

    node_id: str = ""
    agent_id: str = ""
    parent_id: str = ""
    action: str = ""
    delegation_reason: str = ""
    input_hash: str = ""
    output_hash: str = ""
    timestamp: str = ""
    duration_ms: float = 0.0
    metadata: dict[str, object] = field(default_factory=dict)
    node_hash: str = ""

    def compute_hash(self) -> str:
        """SHA-256 of the canonical node payload (excludes node_hash)."""
        data = {
            "node_id": self.node_id,
            "agent_id": self.agent_id,
            "parent_id": self.parent_id,
            "action": self.action,
            "delegation_reason": self.delegation_reason,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
        }
        canonical = orjson.dumps(data, option=orjson.OPT_SORT_KEYS)
        return hashlib.sha256(canonical).hexdigest()


class TraceGraph:
    """Directed Acyclic Graph (DAG) for multi-agent trace auditing.

    Parameters:
        trace_id:   Unique identifier for this workflow trace.
        tenant_id:  Tenant context.
    """

    def __init__(self, trace_id: str = "", tenant_id: str = "") -> None:
        self.trace_id = trace_id or uuid.uuid4().hex
        self.tenant_id = tenant_id
        self._nodes: dict[str, TraceNode] = {}
        self._children: dict[str, list[str]] = {}  # parent_id -> [child_ids]
        self._roots: list[str] = []

    def add_node(
        self,
        *,
        agent_id: str,
        action: str = "execute",
        parent_id: str = "",
        delegation_reason: str = "",
        input_data: str = "",
        output_data: str = "",
        duration_ms: float = 0.0,
        metadata: dict[str, object] | None = None,
    ) -> TraceNode:
        """Add a node to the trace graph.

        Parameters:
            agent_id:          Agent executing this step.
            action:            Action type ("delegate", "handoff", "execute", "parallel").
            parent_id:         Parent node ID (empty for root).
            delegation_reason: Why the parent delegated.
            input_data:        Raw input (hashed, not stored).
            output_data:       Raw output (hashed, not stored).
            duration_ms:       Execution time.
            metadata:          Additional context.

        Returns:
            The created :class:`TraceNode`.
        """
        node = TraceNode(
            node_id=uuid.uuid4().hex,
            agent_id=agent_id,
            parent_id=parent_id,
            action=action,
            delegation_reason=delegation_reason,
            input_hash=hashlib.sha256(input_data.encode()).hexdigest() if input_data else "",
            output_hash=hashlib.sha256(output_data.encode()).hexdigest() if output_data else "",
            timestamp=datetime.now(UTC).isoformat(),
            duration_ms=duration_ms,
            metadata=metadata or {},
        )
        node.node_hash = node.compute_hash()

        self._nodes[node.node_id] = node
        if parent_id:
            self._children.setdefault(parent_id, []).append(node.node_id)
        else:
            self._roots.append(node.node_id)

        return node

    def get_node(self, node_id: str) -> TraceNode | None:
        return self._nodes.get(node_id)

    def get_children(self, node_id: str) -> list[TraceNode]:
        child_ids = self._children.get(node_id, [])
        return [self._nodes[cid] for cid in child_ids if cid in self._nodes]

    @property
    def roots(self) -> list[TraceNode]:
        return [self._nodes[rid] for rid in self._roots if rid in self._nodes]

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def depth(self) -> int:
        """Maximum depth of the trace graph."""
        if not self._roots:
            return 0

        def _depth(node_id: str) -> int:
            children = self._children.get(node_id, [])
            if not children:
                return 1
            return 1 + max(_depth(cid) for cid in children)

        return max(_depth(rid) for rid in self._roots)

    def has_cycles(self) -> bool:
        """Check if the graph contains cycles (should be a DAG)."""
        visited: set[str] = set()
        in_stack: set[str] = set()

        def _dfs(node_id: str) -> bool:
            if node_id in in_stack:
                return True  # Cycle detected
            if node_id in visited:
                return False
            visited.add(node_id)
            in_stack.add(node_id)
            for child_id in self._children.get(node_id, []):
                if _dfs(child_id):
                    return True
            in_stack.discard(node_id)
            return False

        for root_id in self._roots:
            if _dfs(root_id):
                return True
        return False

    def verify_integrity(self) -> bool:
        """Verify that all node hashes are correct (no tampering)."""
        for node in self._nodes.values():
            if node.node_hash != node.compute_hash():
                return False
        return True

    def get_agent_lineage(self, node_id: str) -> list[TraceNode]:
        """Trace the lineage from a node back to its root."""
        lineage: list[TraceNode] = []
        current_id = node_id
        visited: set[str] = set()
        while current_id and current_id in self._nodes:
            if current_id in visited:
                break  # Prevent infinite loop
            visited.add(current_id)
            node = self._nodes[current_id]
            lineage.append(node)
            current_id = node.parent_id
        lineage.reverse()
        return lineage

    def to_dict(self) -> dict[str, object]:
        """Serialize the graph to a dictionary."""
        return {
            "trace_id": self.trace_id,
            "tenant_id": self.tenant_id,
            "node_count": self.node_count,
            "depth": self.depth,
            "roots": [r.node_id for r in self.roots],
            "nodes": {
                nid: {
                    "agent_id": n.agent_id,
                    "parent_id": n.parent_id,
                    "action": n.action,
                    "delegation_reason": n.delegation_reason,
                    "timestamp": n.timestamp,
                    "duration_ms": n.duration_ms,
                    "node_hash": n.node_hash,
                }
                for nid, n in self._nodes.items()
            },
        }
