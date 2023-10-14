# Salsa20 Algorithmus

Verschlüssele und entschlüssele Nachrichten über den Salsa20 Algorithmus von Daniel J. Bernstein.


## Über Salsa20
Bei Salsa20 handelt es sich um eine **symmetrische Stromverschlüsselung**.<br />
Das heißt ein Klartext kann in einen Geheimtext verschlüsselt werden.<br /> Das gleiche gilt umgekehrt, ein bereits mit Salsa20 verschlüsselter Text kann über den Algortihmus entschlüsselt werden.


## Implementierung

### Installation
Erstelle eine Executable mit Make
```bash
cd ./Implementierung
make
```
Die nun erstellte Exectuable heißt `salsa20` und liegt in `Implementierung/`

### Ausführung
Für die Ausführung wird ein Schlüssel (-k), ein Initialisierungsvektor (-i) und eine Eingabedatei mit einer Nachricht angegeben. Standardmäßig wird `Version 0` genutzt.
```bash
salsa20 -k <int>,<int>,<int>,<int>,<int>,<int>,<int>,<int> -i <int> <input-file>
```
Eine Beispielausführung folgt:

```bash
./salsa20 -k 1,2,3,4,5,6,7,8 -i 12 ./examples/klartext.txt
```

Der Schlüssel(Key) wird wie oben als eine `kommaseparierte Liste von 32-Bit vorzeichenlosen Zahlen` angegeben (ohne Whitespace). Der Initialisierungsvektor(auch Nonce) wird als eine `64-Bit vorzeichenlose Zahl` angegeben. Die verschlüsselte oder entschlüsselte Nachricht wird hier standardmäßig in `out.txt` geschrieben.

### Beispielausführungen
Für die folgenden Beispiele, kann die `./examples.zip` extrahiert werden.

#### Verschlüsselung (Encryption)
Verschlüssele die Nachricht in `./examples/klartext.txt `mit einem 256-Bit Key, einer 64-Bit Nonce und schreibe die Ausgabe in `./geheimtext.txt`
```bash
./salsa20 -k 4294967295,4294967294,4294967293,4294967292,4294967291,429496720,429496,1 -i 8397434398 -o ./geheimtext.txt ./examples/klartext.txt
```
Die Ausgabedatei wird durch die Option (-o) spezifiziert.

#### Entschlüsselung (Decryption)
Entschlüssele die Nachricht in `./examples/geheimtext.txt` mit dem gleichen 256-Bit Key und der gleichen 64-Bit Nonce, die zum Verschlüsseln genutzt wurde und schreibe die Ausgabe in `./klartext`
```bash
./salsa20 -k 4294967295,4294967294,4294967293,4294967292,4294967291,429496720,429496,1 -i 8397434398 -o ./klartext.txt ./examples/geheimtext.txt
```

#### Version (-V)
Spezifiziere eine andere Version zum ausführen. Hier z.B. `0`
```bash
./salsa20 -V 2 -k 1,2,3,4,5,6,7,8 -i 12 ./examples/klartext.txt
```

#### Benchmarking (-B)
Wiederhole die Ausführung so oft wie im Argument der Option (-B) angegeben.
Gebe zusätzlich die Dauer aller Ausführungen an, sowie die durchschnittliche Dauer einer Ausführung.
```bash
./salsa20 -B 10 -k 1,2,3,4,5,6,7,8 -i 12 ./examples/klartext.txt
```

#### Tests (-T)
Führe die **Tests** aus um alle Versionen mit vorgefertigten Inputs zu testen.
```bash
./salsa20 -T
```

#### Hilfe (-h)
Gebe die **Hilfeanzeige** aus
```bash
./salsa20 -h
```

#### Kombination von (Version, Benchmark, Output)
Nutze Version 2, führe Salsa20 11 mal aus und gebe die gesamte Ausführungszeit an, schreibe die Ausgabe in die Datei `./geheimtext.txt`
```bash
./salsa20 -V2 -B 10 -k 2294467295,1294967294,3294967293,1294967292,94967291,189496720,329496,1 -i 8397414398 -o ./geheimtext.txt ./examples/klartext.txt
```
und entschlüsselt mit Version 1 und Ausgabe in `./klartext.txt`
```bash
./salsa20 -V1 -k 2294467295,1294967294,3294967293,1294967292,94967291,189496720,329496,1 -i 8397414398 -o ./klartext.txt ./geheimtext.txt
```

Alle anderen `./examples/geheimtext_<size>.txt` wurden mit dem Key `1000000,20000000,300000000,400000000,500000000,600000000,700000000,811111111` und der Nonce `2384675319379984962` verschlüsselt.


### Optionen

| Option     | Optional | Argument                                                          | Default   | Beschreibung                        |
|------------|----------|-------------------------------------------------------------------|-----------|-------------------------------------|
| -V         | ja       | ja, eine Version in [0,4]			                                    | 0					| Spezifiziert die verwendete Version |
| -B         | ja       | ja, die Anzahl der zusätzlichen Ausführungen                      | 0         | Misst die durchschnittliche Ausführungsdauer des implementierten Salsa20 Algorithmus, wenn gesetzt |
| -T         | ja       |                                                                   | -         | Testet die Implementierung durch vorgefertigte Tests |
| -k         | nein     | ja, eine kommaseparierte Liste von 32-Bit vorzeichenlosen Zahlen  | -         | Der Schlüssel des Salsa20 Alogrithmus
| -i         | nein     | ja, die verwendete 64-Bit-Nonce                                   | -         | Die Nonce des Salsa20 Algorithmus  
| -o         | ja       | ja, ein Pfad zu einer Ausgabedatei                                | "out.txt" | Ausgabedatei
| -h, --help | ja       |                                                                   | -         | Gibt die Hilfe aus

Optionen die **nicht** `"Optional"` sind müssen immer spezifiert werden.


### Versionen

| Version | Beschreibung                            |
|---------|-----------------------------------------|
| 0       | SIMD optimierte Version                 |
| 1       | SIMD naiv                               |
| 2       | Ohne Matrix-Transposition Optimierung   |
| 3       | Erste naive Implementierung             |


### Entwicklerteam
- Adam Karamelo
- Caner Ciboglu
- Philipp Czernitzki

### Credit für Beispiele
Quellen für ./examples.zip, aufgerufen am 24. Juli 2022
- Spaceipsum https://spaceipsum.com/we-choose-to-go-to-the-moon/\
klartext.txt\
klartext_1mb.txt\
klartext_424kb.txt
- Cupcake Ipsum http://www.cupcakeipsum.com/\
klartext_81kb.txt
