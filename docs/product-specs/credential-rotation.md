# Credential-Rotation

**Status:** Verifiziert

## Nutzerziel

Ein Windows- oder Linux-Benutzer kann ein Forgejo-Zugriffstoken ersetzen, ohne es in
Argumenten, Projektdateien, Logs oder MCP-Transkripten offenzulegen.

## Produktverhalten

- Die CLI akzeptiert keine Argumente und liest den Kandidaten nur von stdin.
- Store- und HTTPS-Verfügbarkeit werden vor einer Speicherung geprüft.
- Der Kandidat wird vor dem Schreiben statusbasiert bei Forgejo validiert.
- Eine benutzerbezogene Sperre serialisiert konkurrierende Rotationen.
- Readback wird per gewöhnlichem exaktem lokalem Gleichheitsvergleich geprüft; es gibt keinen
  angreiferbeobachtbaren Vergleichsorakel. Fehler führen zu verifiziertem
  Rollback oder einem explizit unbekannten Credential-Zustand.
- Die Ausgabe ist ein einzelnes redigiertes JSON-Ergebnis mit dokumentiertem
  Exit-Code und Neustartanforderung.

## Akzeptanzkriterien

- Kein Ergebnis, Fehler, Argument oder Repräsentationsstring enthält das Token.
- Ein abgelehnter Kandidat verursacht keinen Store-Schreibzugriff.
- Erfolg wird erst nach erfolgreichem Readback gemeldet.
- Fehlgeschlagener Readback stellt den vorherigen Zustand wieder her oder löscht
  einen neu angelegten Datensatz und verifiziert das Ergebnis.
- Der laufende MCP-Server behält sein Start-Credential und muss neu gestartet
  werden.
- Linux verwendet ausschließlich `SecretStorage>=3.5,<4; sys_platform == 'linux'` mit einer
  bestehenden entsperrten `default`-Collection und genau einem festen Item; Provisionierung,
  Unlock, Prompt, `secret-tool`, externe Kommandos, Raw-D-Bus und Datei-Fallbacks sind verboten.
- Vollständige Bash-/PowerShell-Beispiele und Troubleshooting stehen in
  [credential-launch.md](../credential-launch.md) und [credential-rotation.md](../credential-rotation.md).
