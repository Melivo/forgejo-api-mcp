# Planungskonventionen

## Ablage

- Architektur- und API-Entwürfe liegen unter `docs/plans/designs/`.
- Ausführungspläne liegen unter `docs/plans/work/`.
- Beide Verzeichnisse sind lokale Arbeitsnotizen und standardmäßig git-ignoriert.
- Ein Plan, auf den dauerhaft verwiesen wird, wird bewusst mit `git add -f`
  promoviert.

Dateinamen beginnen je Unterordner mit einer dreistelligen fortlaufenden Nummer,
zum Beispiel `001-linux-credentials.md`.

## Status

Designpläne verwenden `Draft` oder `Approved`. Ausführungspläne verwenden
`Active` oder `Completed`. Der Status steht direkt unter dem Titel.

## Mindestinhalt

Ein Plan nennt Ziel, Nicht-Ziele, betroffene Verträge, Schritte, Risiken,
Verifikation und offene Entscheidungen. Ausführungspläne führen zusätzlich einen
Fortschritts- und Entscheidungslog.

## Vorlage

```markdown
# Titel

**Status:** Active

## Ziel
## Nicht-Ziele
## Verträge und Grenzen
## Arbeitsschritte
## Risiken
## Verifikation
## Entscheidungslog
```

Pläne ersetzen keine verifizierten Architekturentscheidungen. Dauerhafte Gründe
und Konsequenzen werden nach Abschluss in `docs/design-docs/` überführt.
