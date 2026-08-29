# Forgejo-API-Adapter

**Status:** Verifiziert

## Nutzerziel

Ein MCP-Client kann den gebündelten Forgejo-Vertrag durchsuchen, eine Operation
prüfen und sie mit klar getrennten Eingabegruppen ausführen, ohne für jede
REST-Operation ein eigenes Tool zu benötigen.

## Produktverhalten

- Discovery zeigt Operation, Parameter, Medienformate und Mutationsmerkmale.
- Detailansicht liefert den vollständig normalisierten Aufrufvertrag.
- Invocation validiert Pfad, Query, Header, Body, Form und Dateien vor dem
  Netzwerkzugriff.
- Schreibende Aufrufe werden nicht simuliert oder verzögert.
- Ergebnisse sind größenbegrenzt, strukturierte Fehler enthalten keine Secrets.

## Akzeptanzkriterien

- Der Katalog lädt die geprüfte Forgejo-Version und enthält genau die erwartete
  Zahl eindeutiger Operationen.
- Jede katalogisierte Operation lässt sich vertragskonform serialisieren.
- Der Prozess verwendet ausschließlich lokalen MCP-`stdio`-Transport.
- Unsichere Basis-URLs, geschützte Headerüberschreibungen und übergroße Eingaben
  werden abgelehnt.
- Vor mutierenden Aufrufen bestätigt der Benutzer Operation, Ziel und Effekt im
  aufrufenden Client oder Agenten.
