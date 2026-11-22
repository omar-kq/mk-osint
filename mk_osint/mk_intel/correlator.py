"""Entity Correlation Engine & Relationship Graph Exporter (JSON, Mermaid, Graphviz DOT)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Set, Tuple

from mk_core.models import OSINTResult, ScanStatus


@dataclass
class GraphNode:
    node_id: str
    node_type: str  # target | profile | email | username | phone | domain | ip | file | location | person
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    module: str
    confidence: float = 1.0


@dataclass
class CorrelationGraph:
    """In-memory OSINT entity relationship graph with multi-format exporters."""

    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)
    pivots: List[str] = field(default_factory=list)
    _edge_keys: Set[Tuple[str, str, str]] = field(default_factory=set, repr=False)

    def add_node(self, node_id: str, node_type: str, label: str, **meta: Any) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                node_id=node_id, node_type=node_type, label=label, metadata=meta
            )
        elif meta:
            self.nodes[node_id].metadata.update(meta)
        return node_id

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        module: str,
        confidence: float = 1.0,
    ) -> None:
        key = (source, target, relation)
        if key not in self._edge_keys:
            self._edge_keys.add(key)
            self.edges.append(
                GraphEdge(
                    source=source,
                    target=target,
                    relation=relation,
                    module=module,
                    confidence=confidence,
                )
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "pivots": self.pivots,
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self.edges],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_mermaid(self) -> str:
        """Export graph as a Mermaid flowchart (renders directly in GitHub/Markdown)."""
        lines = ["graph LR"]
        safe_ids: Dict[str, str] = {}
        for idx, (nid, node) in enumerate(self.nodes.items(), start=1):
            sid = f"N{idx}"
            safe_ids[nid] = sid
            clean_label = node.label.replace('"', "'")
            lines.append(f'    {sid}["{node.node_type.upper()}: {clean_label}"]')
        for edge in self.edges:
            if edge.source in safe_ids and edge.target in safe_ids:
                lines.append(
                    f"    {safe_ids[edge.source]} -->|{edge.relation}| {safe_ids[edge.target]}"
                )
        return "\n".join(lines)

    def to_graphviz_dot(self) -> str:
        """Export graph as Graphviz DOT format for Kali `dot -Tpng` rendering."""
        lines = ['digraph MK_OSINT {', '    rankdir=LR;', '    node [shape=box, style=rounded];']
        for nid, node in self.nodes.items():
            escaped_id = nid.replace('"', '\\"')
            escaped_label = f"{node.node_type.upper()}\\n{node.label}".replace('"', '\\"')
            lines.append(f'    "{escaped_id}" [label="{escaped_label}"];')
        for edge in self.edges:
            s = edge.source.replace('"', '\\"')
            t = edge.target.replace('"', '\\"')
            rel = edge.relation.replace('"', '\\"')
            lines.append(f'    "{s}" -> "{t}" [label="{rel}"];')
        lines.append("}")
        return "\n".join(lines)


class EntityCorrelator:
    """Builds a unified CorrelationGraph from isolated per-module OSINTResult lists."""

    @staticmethod
    def build_graph(results: List[OSINTResult]) -> CorrelationGraph:
        graph = CorrelationGraph()
        seen_usernames: Set[str] = set()
        email_candidates: Dict[str, str] = {}  # candidate_username -> email_node_id

        for res in results:
            if res.status not in {ScanStatus.FOUND, ScanStatus.PASSIVE_DORK}:
                continue

            root_id = f"{res.target_type.value}:{res.target.lower()}"
            graph.add_node(root_id, res.target_type.value, res.target)

            if res.target_type.value == "username":
                seen_usernames.add(res.target.lower())

            # 1. Link discovered profiles / URLs
            if res.status == ScanStatus.FOUND and res.url:
                prof_id = f"profile:{res.source_name}:{res.url}"
                graph.add_node(prof_id, "profile", f"{res.source_name} ({res.url})", url=res.url)
                graph.add_edge(root_id, prof_id, "has_account_on", res.module_name)

            data = res.extracted_data or {}

            # 2. Email -> domain & candidate usernames
            if "domain" in data and res.target_type.value == "email":
                dom_val = str(data["domain"]).lower()
                dom_id = f"domain:{dom_val}"
                graph.add_node(dom_id, "domain", dom_val)
                graph.add_edge(root_id, dom_id, "uses_domain", res.module_name)

            for cand in data.get("candidate_usernames", []):
                cand_l = str(cand).lower()
                cand_id = f"username:{cand_l}"
                graph.add_node(cand_id, "username", cand_l, inferred=True)
                graph.add_edge(root_id, cand_id, "suggests_username", res.module_name, confidence=0.7)
                email_candidates[cand_l] = root_id

            # 3. Link-in-Bio outbound linked accounts
            for ext_url in data.get("linked_accounts", []):
                ext_id = f"profile:bio:{ext_url}"
                graph.add_node(ext_id, "profile", ext_url, url=ext_url)
                graph.add_edge(root_id, ext_id, "links_to", res.module_name)

            # 4. Phone -> Country & Carrier
            if "carrier_or_region" in data and res.target_type.value == "phone":
                carrier = str(data["carrier_or_region"])
                c_id = f"carrier:{carrier}"
                graph.add_node(c_id, "telecom", f"{carrier} ({data.get('country', '')})")
                graph.add_edge(root_id, c_id, "registered_prefix", res.module_name)

            # 5. Domain -> Subdomains & MX hosts
            for sub in data.get("subdomains", [])[:15]:
                sub_id = f"domain:{str(sub).lower()}"
                graph.add_node(sub_id, "domain", str(sub).lower())
                graph.add_edge(root_id, sub_id, "has_subdomain", res.module_name)

            # 6. File metadata -> Author / Creator & GPS Location
            for author_key in ("creator", "author", "Artist", "lastModifiedBy"):
                if author_key in data and data[author_key]:
                    person = str(data[author_key]).strip()
                    p_id = f"person:{person.lower()}"
                    graph.add_node(p_id, "person", person)
                    graph.add_edge(root_id, p_id, f"metadata_{author_key.lower()}", res.module_name)

            if "latitude" in data and "longitude" in data:
                coord = f"{data['latitude']}, {data['longitude']}"
                loc_id = f"location:{coord}"
                graph.add_node(loc_id, "location", coord, maps_url=res.url)
                graph.add_edge(root_id, loc_id, "geotagged_at", res.module_name)

        # Cross-module pivot detection: email candidate matches a scanned/found username
        for uname in seen_usernames:
            if uname in email_candidates:
                pivot_msg = f"Cross-module pivot: username '{uname}' matches candidate from {email_candidates[uname]}"
                graph.pivots.append(pivot_msg)
                graph.add_edge(
                    email_candidates[uname],
                    f"username:{uname}",
                    "correlated_identity",
                    "correlator",
                    confidence=0.9,
                )

        return graph
