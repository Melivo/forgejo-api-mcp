# Code-Review

## Schweregrade

- **Blocker:** Secret-Leak, unbestätigte Mutation, unsicherer Netzwerkpfad,
  Datenverlust oder nicht rückrollbare Credential-Änderung.
- **Major:** Vertragsbruch, falsche Serialisierung, fehlende Begrenzung,
  Plattformregression oder unstrukturierter erwarteter Fehler.
- **Minor:** Wartbarkeitsproblem mit begrenzter Wirkung oder fehlender gezielter
  Testnachweis.
- **Nit:** Rein lokale Lesbarkeit oder Stil ohne Verhaltensrisiko.

## Checkliste

- Stimmt das Verhalten mit dem gebündelten Swagger-Vertrag überein?
- Bleibt die Abhängigkeit `server → client → catalog` klar und wird
  Plattformlogik aus dem normalen API-Pfad herausgehalten?
- Werden ungültige Eingaben vor Netzwerk- oder Store-Zugriff abgelehnt?
- Bleiben Timeouts, Größenlimits, HTTPS, Redirect- und Proxyregeln erhalten?
- Können Token, Header, Antwortkörper oder Credential-Blobs in Ausgabe,
  Exceptions oder Repräsentationen gelangen?
- Sind mutierende und destruktive Operationen korrekt sichtbar und ist der
  Bestätigungsvertrag dokumentiert?
- Decken Tests Erfolg, Grenzen und relevante Fehler-/Rollbackpfade ab?
- Sind Snapshot-Version, Operationsdiff und Paketartefakte geprüft, falls der
  Vertrag geändert wurde?
- Stimmen README, Wartungs- und Credential-Dokumente mit geändertem Verhalten
  überein?

## Domänenschwerpunkte

`client.py` verlangt besonderes Augenmerk auf Schema-Validierung,
Serialisierungsäquivalenz, Secret-Redaktion und Ressourcengrenzen.
`credentials.py` und `rotate.py` verlangen Plattform-, FFI-, Konkurrenz- und
Rollbackprüfung. `openapi.json` verlangt vollständige Konformitäts- und
Paketprüfung.

## Zu meldende Anti-Patterns

- Einzeltools für neue Forgejo-Endpunkte statt Nutzung des Vertragsadapters.
- Runtime-Download des Swagger-Dokuments.
- Tokenübergabe über CLI-Argumente oder Projektkonfiguration.
- Catch-all-Ausnahmen, die Credential-Zustand oder Transportursache verschleiern.
- Neue unbeschränkte Eingabe-, Upload- oder Antwortpfade.
- Hot Reload, der die dokumentierte Start-Snapshot-Semantik umgeht.

## Menschliches Review

Automatische Freigabe ist nur für nachweislich reine Dokumentations- oder
mechanische Teständerungen ohne Vertragsänderung vertretbar. Security-,
Credential-, Mutations-, Snapshot- und Release-Gate-Änderungen benötigen
menschliches Review. Bei Blocker- oder Major-Befunden keine Freigabe erteilen.
