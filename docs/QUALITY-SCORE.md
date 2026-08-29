# Qualitätsbewertung

Bewertungsskala: A = stark automatisiert und klar begrenzt, B = solide mit
bekannten Lücken, C = relevante Risiken oder fehlende Nachweise.

| Bereich | Note | Nachweis | Nächste Lücke |
|---|---:|---|---|
| API-Katalog und Vertrag | A | Unveränderlicher Snapshot, Referenzauflösung, 467-Operationen-Konformitätstest | Snapshot-Updates bleiben manuell |
| HTTP-Validierung und Serialisierung | A- | Strikte Schemaprüfung, Größen- und URL-Grenzen, geschützte Header | `client.py` ist ein großer Änderungshotspot |
| Secret- und Transport-Sicherheit | A- | HTTPS, keine Redirects/Proxys, Antwortredaktion, Leakage-Tests | Launcher-Interop braucht manuellen Windows-Gate |
| Credential-Rotation | A- auf Windows und Linux | Validate-before-write, plattformspezifischer Lock, Readback, Rollback, Exit-Codes | Live Secret-Service-Smoke opt-in |
| MCP-Laufzeit | A | Nur `stdio`, Lifecycle- und Launch-Smoke-Tests | Keine Laufzeitmetriken; für lokalen Prozess derzeit akzeptiert |
| Paketierung | A- | Wheel-/sdist-Isolationstest mit gebündeltem Katalog; CI-Matrix Ubuntu/Windows mit Python 3.12, 3.13 und 3.14 | Keine offene Matrix-Folgearbeit |
| Dokumentation | A- | `oma docs verify --json`: 20 Dokumente, 45 Referenzen, 0 gebrochene Referenzen; kanonische Launch-/Rotationsguides und Tests | Keine bestätigte Drift im aktuellen Stand |

## Aktualisierung

Noten ändern sich nur mit einem konkreten Nachweis oder einer neu entdeckten
Lücke. Jede Abwertung erhält einen Eintrag im lokalen
[Tech-Debt-Tracker](plans/work/tech-debt-tracker.md); jede Aufwertung nennt den
Test, das Review oder die Betriebsprüfung, die sie rechtfertigt.
