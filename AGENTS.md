# Forgejo API MCP

> Lokaler, vertragsgetriebener MCP-Server für die Forgejo-REST-API.

## Architektur

Siehe [ARCHITECTURE.md](ARCHITECTURE.md) für Domänen, Schichtung,
Integrationspunkte und Datenflüsse.

## Dokumentation

- [Designentscheidungen](docs/design-docs/index.md) - verifizierte Gründe und
  Kernüberzeugungen.
- [Pläne](docs/PLANS.md) - Ablage, Status und Vorlagen für lokale Arbeitspläne.
- [Produktspezifikationen](docs/product-specs/index.md) - sichtbare
  Produktverträge und Akzeptanzkriterien.
- [Externe Referenzen](docs/references/index.md) - Richtlinie und Kandidaten für
  LLM-optimierte Bibliotheksnotizen.
- [Wartung](docs/maintenance.md) - Snapshot-Updates, Gates und Betriebsworkflow.
- [Credential-Launch](docs/credential-launch.md) - sicherer lokaler Startpfad
  für Windows Credential Manager und Linux Secret Service.
- [Credential-Rotation](docs/credential-rotation.md) - Rotation, Exit-Codes und
  manueller Release-Gate.

## Qualitäts- und Betriebsleitfäden

- [Qualitätsbewertung](docs/QUALITY-SCORE.md) - Nachweise, Noten und Lücken.
- [Code-Review](docs/CODE-REVIEW.md) - Schweregrade, Checkliste und
  Human-Review-Gates.
- [Zuverlässigkeit](docs/RELIABILITY.md) - Laufzeit-, Ressourcen- und
  Fehlerverträge.
- [Sicherheit](docs/SECURITY.md) - Secrets, Netzwerkgrenzen und Mutationsregeln.
- [Tech Debt](docs/plans/work/tech-debt-tracker.md) - bekannte Schulden und
  vorgeschlagene Auflösung; lokal git-ignoriert.

## Projektstruktur

Dies ist ein einzelnes Python-Paket, kein Monorepo. `src/forgejo_api_mcp/` enthält
Katalog, HTTP-Adapter, MCP-Grenze und Credential-Rotation. `tests/` kombiniert
Unit-, Integration-, Smoke-, Vertragskonformitäts- und Paketinstallationstests.
Es gibt keine zusätzlichen Boundary-`AGENTS.md`-Dateien.

## Arbeiten im Repository

- Python 3.12 oder neuer und `uv` verwenden.
- Mindestprüfung: `uv run ruff check .` und `uv run pytest`.
- Snapshot-Änderungen zusätzlich nach [docs/maintenance.md](docs/maintenance.md)
  prüfen und Version sowie Operationsdiff festhalten.
- Lokale Pläne unter `docs/plans/designs/` oder `docs/plans/work/` anlegen; nur
  bewusst referenzierte Pläne mit `git add -f` aufnehmen.

## Schnellregeln

- Vor jedem mutierenden oder destruktiven Forgejo-Aufruf explizite
  Benutzerbestätigung für `operation_id`, Ziel und Effekt einholen.
- Tokens nie in Argumente, Dateien, Konfiguration, Logs, Fehler oder Testausgabe
  aufnehmen; Rotation liest Tokens ausschließlich von stdin.
- Nur MCP über lokalen `stdio`-Transport anbieten; keinen HTTP-, SSE- oder
  Streamable-HTTP-Listener ergänzen.
- Den Swagger-Vertrag bündeln und geprüft aktualisieren; keinen Laufzeitabruf der
  Spezifikation einführen.
- HTTPS-, Redirect-, Proxy-, Timeout-, Größen-, Redaktions- und
  Start-Snapshot-Regeln als Produktverträge behandeln.
- Plattformlogik im Credential-Pfad halten; den normalen Katalog-/Client-/Server-
  Pfad nicht für Windows oder Linux duplizieren.

<!-- MANUAL: Notes below this line are preserved on regeneration -->
