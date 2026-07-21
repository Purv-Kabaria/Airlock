"""The SQL analyzer: parse, qualify, resolve columns to URNs, and rewrite in flight.

Nothing here talks to a warehouse or DataHub. It turns SQL text plus a PolicyGraph into a
`ResolvedQuery` (every reference bound to a catalog fact) and, given a decision, a rewritten
statement. This is the crown jewel; it is covered by property-based tests.
"""
