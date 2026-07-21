"""Airlock: a governance gateway between AI agents (MCP) and a SQL warehouse.

Policy is compiled live from a DataHub catalog; every query is parsed to an AST,
resolved to catalog URNs, decided against the policy, rewritten in flight, executed,
and returned with a machine-readable verdict envelope.
"""

__version__ = "0.1.0"
