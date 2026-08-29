# Kernüberzeugungen

## Vertrag vor Netzwerk

Jeder Forgejo-Aufruf beginnt mit einem bekannten `operation_id` aus dem
gebündelten Vertrag. Unbekannte Parameter, ungültige Schematypen und unsichere
Konfiguration werden vor dem Netzwerkzugriff abgelehnt.

## Reproduzierbar statt dynamisch

Der API-Vertrag ist ein geprüftes Paketartefakt. Laufzeitstarts dürfen nicht von
einem entfernten Spezifikationsabruf abhängen; Snapshot-Änderungen brauchen einen
Versions- und Operationsdiff sowie Tests.

## Geheimnisse minimieren

Tokens gehören weder in Argumente, Projektdateien, Konfiguration, Logs noch
Antworten. Persistente lokale Speicherung erfolgt über Windows Credential Manager
oder Linux Secret Service; der MCP-Prozess erhält das Token nur in seiner
Kindprozessumgebung.

## Grenzen sind Teil des Produkts

Timeouts, Eingabe-, Upload- und Antwortgrößen sowie deaktivierte Redirects und
Umgebungs-Proxys sind keine Optimierungen, sondern Sicherheits- und
Zuverlässigkeitsverträge. Änderungen daran brauchen explizite Tests.

## Schreiben braucht menschliche Absicht

Der Server führt mutierende Operationen unmittelbar aus. Deshalb muss der
aufrufende Client oder Agent vor jedem mutierenden oder destruktiven Aufruf die
explizite Zustimmung für Operation, Ziel und Effekt einholen.

## Verhalten ist automatisiert nachweisbar

Die Tests decken Toolregistrierung, Katalog, HTTP-Serialisierung, alle 467
Operationen, Paketinstallation, MCP-Lebenszyklus und Secret-Redaktion ab.
Plattformspezifische Live-Credential-Interop bleibt zusätzlich ein redigierter
manueller Release-Gate.
