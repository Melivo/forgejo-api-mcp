# Externe Referenzen

Derzeit sind keine vendierten LLM-Referenzdateien erforderlich. Die zwei
tragenden externen Abhängigkeiten sind:

- MCP Python SDK: relevant für Tool-Schema, Annotationen und `stdio`-Lifecycle.
- HTTPX: relevant für Streaming, Timeout-Semantik und Transporttests.

Eine `{library}-llms.txt`-Datei soll erst ergänzt werden, wenn wiederkehrende
Fehlanwendung oder schwer auffindbare versionsgebundene Regeln einen lokalen
Auszug rechtfertigen. Projektentscheidungen gehören stattdessen nach
`docs/design-docs/`.
