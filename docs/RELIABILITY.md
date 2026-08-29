# Zuverlässigkeit

## Laufzeitvertrag

Der Server ist ein lokaler `stdio`-Prozess ohne eingehenden Netzwerkport. stdout
ist ausschließlich für MCP-Protokollframes reserviert. Der allgemeine
Forgejo-Aufruf ist mit einem absoluten und HTTPX-internen Timeout von höchstens
30 Sekunden begrenzt; Redirects und Umgebungs-Proxys bleiben deaktiviert.

## Ressourcenbegrenzung

- Parameter und serialisierte Request-Bodies sind auf 1 MB begrenzt.
- Einzelne und aggregierte Uploads sind auf 10 MB begrenzt.
- Text-/JSON-Antworten sind auf 1 MB, Binärantworten auf 10 MB begrenzt.
- Zu lange URLs werden vor HTTPX abgelehnt.
- Trunkierte Text- und Binärantworten tragen explizite Metadaten.

Diese Grenzen sind Verträge. Änderungen erfordern Grenzwert- und
Regressionsprüfungen, nicht nur eine Konstantenanpassung.

## Fehlerverhalten

Validierungs- und Konfigurationsfehler werden vor dem Netzwerkzugriff als
Domänenausnahmen ausgelöst. Timeout-, Transport- und HTTP-Fehler werden in
strukturierte, redigierte Ergebnisse übersetzt. Provider-Auth-Proben werten nur
den Status aus und konsumieren keinen Antwortkörper.

## Zustandsmodell

Der MCP-Server hält Katalog, Basis-URL und Token als Prozess-Snapshot. Es gibt
keinen Hot Reload. Nach Credential-Rotation ist ein Neustart erforderlich; diese
Semantik darf weder aus einem erfolgreichen Probeaufruf noch aus Store-Zustand
abgeleitet werden.

## Verifikation und Betrieb

- Vor Änderungen: betroffene Unit- und Integrationstests identifizieren.
- Mindestgate: `uv run ruff check .` und `uv run pytest`.
- Snapshot-Änderungen folgen zusätzlich [maintenance.md](maintenance.md).
- Credential-Release-Abnahme enthält den redigierten manuellen Windows-Interop-
  Gate aus [credential-rotation.md](credential-rotation.md).
- CI prüft Ubuntu und Windows mit Python 3.12, 3.13 und 3.14: `uv sync --locked`, Ruff,
  Paketinstallation, vollständige Tests und MCP-Lifecycle. Der Secret-Service-Smoke-Test ist
  nur per Workflow-Dispatch opt-in, synthetisch und in `dbus-run-session` isoliert.
- Linux-SecretStorage-Operationen haben ein 5-Sekunden-Gesamtlimit pro Worker; bei mutierenden
  Timeouts ist der Zustand unbestimmt und muss redigiert reconciliert werden. Der per-user Lock
  wartet höchstens 30 Sekunden.

Formale SLOs und Error Budgets sind für den lokalen, vom Host verwalteten Prozess
nicht definiert. <!-- TODO: confirm this rule -->
