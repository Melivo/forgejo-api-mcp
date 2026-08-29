# Start-Snapshot für Credentials

**Status:** Verifiziert
**Entscheidung:** Basis-URL und Zugriffstoken werden beim Prozessstart einmal in
den HTTP-Client übernommen; Rotation verändert den laufenden Prozess nicht.

## Kontext

Ein Credential-Store-Lookup bei jedem Toolaufruf würde Plattformlogik und
Secretzugriff in den allgemeinen API-Pfad ziehen. Gleichzeitig muss ein
abgelaufenes Token sicher ersetzt und diagnostiziert werden können.

## Betrachtete Optionen

1. Projektinterne Rotations-CLI plus read-only Statusprobe und anschließender
   Neustart.
2. Hot Reload oder Credential-Store-Lookup während laufender MCP-Aufrufe.
3. Erweiterung eines externen Launch-Wrappers um die Rotation.

## Begründung

Option 1 hält die Serverlaufzeit plattformneutral und deterministisch. Die
projektinterne CLI ist testbar und kann Validate-before-write, Mutex, Readback,
Rollback und redigierte Ergebnisse kontrollieren.

## Konsequenzen

- Nach erfolgreicher Rotation ist ein Neustart immer erforderlich.
- `provider_auth_status` prüft ausschließlich den Start-Snapshot und liest den
  Credential Store nicht erneut.
- Launcher und Dokumentation müssen die Neustartsemantik sichtbar erhalten.
- Der Linux-Secret-Service-Adapter erhält dieselbe Snapshot- und Neustartsemantik.
