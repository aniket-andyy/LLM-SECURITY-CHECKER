"""LangGraph workflow construction."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from app.graph.nodes import GraphNodes, ScanServices, SUCCESS_RESULTS
from app.graph.state import ScanState


def route_after_success(state: ScanState) -> str:
    if state.get("last_attack_success") in SUCCESS_RESULTS:
        return "record_finding"
    return "decide_next_attack"


def route_after_record(state: ScanState) -> str:
    if state.get("last_finding_id"):
        return "update_vulnerability_memory"
    return "decide_next_attack"


def route_after_decision(state: ScanState) -> str:
    if state.get("should_continue"):
        return "generate_attack"
    return "evaluate_defense"


def build_graph(services: ScanServices):
    nodes = GraphNodes(services)
    graph = StateGraph(ScanState)

    graph.add_node("initialize_scan", nodes.initialize_scan)
    graph.add_node("plan_scan", nodes.plan_scan)
    graph.add_node("generate_attack", nodes.generate_attack)
    graph.add_node("send_attack", nodes.send_attack)
    graph.add_node("collect_evidence", nodes.collect_evidence)
    graph.add_node("run_deterministic_checks", nodes.run_deterministic_checks)
    graph.add_node("evaluate_attack_success", nodes.evaluate_attack_success)
    graph.add_node("record_finding", nodes.record_finding)
    graph.add_node("update_vulnerability_memory", nodes.update_vulnerability_memory)
    graph.add_node("assess_blast_radius", nodes.assess_blast_radius)
    graph.add_node("decide_next_attack", nodes.decide_next_attack)
    graph.add_node("evaluate_defense", nodes.evaluate_defense)
    graph.add_node("generate_final_report", nodes.generate_final_report)
    graph.add_node("cleanup", nodes.cleanup)

    graph.set_entry_point("initialize_scan")

    graph.add_edge("initialize_scan", "plan_scan")
    graph.add_edge("plan_scan", "generate_attack")
    graph.add_edge("generate_attack", "send_attack")
    graph.add_edge("send_attack", "collect_evidence")
    graph.add_edge("collect_evidence", "run_deterministic_checks")
    graph.add_edge("run_deterministic_checks", "evaluate_attack_success")

    graph.add_conditional_edges(
        "evaluate_attack_success",
        route_after_success,
        {
            "record_finding": "record_finding",
            "decide_next_attack": "decide_next_attack",
        },
    )

    graph.add_conditional_edges(
        "record_finding",
        route_after_record,
        {
            "update_vulnerability_memory": "update_vulnerability_memory",
            "decide_next_attack": "decide_next_attack",
        },
    )

    graph.add_edge("update_vulnerability_memory", "assess_blast_radius")
    graph.add_edge("assess_blast_radius", "decide_next_attack")

    graph.add_conditional_edges(
        "decide_next_attack",
        route_after_decision,
        {
            "generate_attack": "generate_attack",
            "evaluate_defense": "evaluate_defense",
        },
    )

    graph.add_edge("evaluate_defense", "generate_final_report")
    graph.add_edge("generate_final_report", "cleanup")
    graph.add_edge("cleanup", END)

    return graph.compile()
