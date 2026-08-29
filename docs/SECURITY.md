# Sicherheit

## Schutzgüter und Vertrauensgrenzen

Primäre Schutzgüter sind das Forgejo-Zugriffstoken, Zielressourcen mutierender
Operationen und die Integrität des gebündelten API-Vertrags. Vertrauensgrenzen
liegen zwischen MCP-Host und Server, Server und Forgejo sowie Rotations-CLI und
the Windows Credential Manager or Linux Secret Service.

## Secret-Regeln

- Tokens niemals in Argumenten, Repositorydateien, dotenv-Dateien, generierter
  Konfiguration, Logs, Fehlern, Beispielen oder Testausgabe speichern.
- `FORGEJO_ACCESS_TOKEN` nur in die Umgebung des MCP-Kindprozesses injizieren.
- Rotation liest den Kandidaten ausschließlich von stdin und gibt nur redigiertes
  JSON aus.
- Repräsentationen von Credential-Datensätzen müssen den Blob redigieren.
- Responses werden gegen rohe, Base64- und JSON-escaped Tokenvarianten redigiert.

## Netzwerkregeln

- Forgejo-Basis-URLs verwenden HTTPS; unsicheres HTTP ist nur für explizite
  localhost-Tests des allgemeinen Clients zulässig.
- Credential-Validierung akzeptiert ausschließlich HTTPS.
- Redirects und Umgebungs-Proxys bleiben deaktiviert.
- Eingaben dürfen Host, `Authorization`, `Host`, `Content-Length` und weitere
  geschützte Transportheader nicht überschreiben.

## Mutierende Operationen

Der Server markiert mutierende und destruktive Verträge, erzwingt aber keine
Bestätigungsinteraktion. Vor Invocation muss der aufrufende Agent oder Client die
explizite Benutzerbestätigung für genaue `operation_id`, Ziel und Effekt einholen.
Discovery und Schemaansicht gelten nicht als Zustimmung.

## Credential-Rotation

Validate-before-write, benutzerbezogene Sperre, vollständiger vorheriger Datensatz,
gewöhnlicher exakter lokaler Readback und verifizierter Rollback sind gemeinsam eine
Transaktionsgrenze. Änderungen an Reihenfolge oder Fehlerzuständen brauchen
Leakage-, Konkurrenz- und Rollback-Tests.

Der lokale Readback ist kein konstantes Vergleichsversprechen; es gibt keinen
angreiferbeobachtbaren Vergleichsorakel.

Linux ist strikt noninteractive: `SecretStorage>=3.5,<4; sys_platform == 'linux'` nutzt nur die
typed API, eine bestehende entsperrte `default`-Collection und genau ein Item mit den festen
Metadaten aus [credential-launch.md](credential-launch.md). Es gibt keinen `secret-tool`-,
externen Kommando-, Raw-D-Bus- oder Datei-Fallback.

## Review-Gates

Menschliches Review ist erforderlich bei Änderungen an Secretfluss,
Authentifizierung, URL-/Headerkontrollen, Antwortredaktion, Credential-FFI,
Mutationskennzeichnung oder dem Swagger-Snapshot. Siehe
[CODE-REVIEW.md](CODE-REVIEW.md).
