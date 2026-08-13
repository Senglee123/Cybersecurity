# Infos
'''
Implemtierung AES Schlüsselfahrplan
Grundsätzlich zwei Unterscheidungen:
 ▶ Vorausberechnung
 ▶ Fließende Berechnung

 Vorrausberechnung:
▶ Schlüsselexpansionsvektor W wird komplett berechnet
▶ Ver- und Entschlüsselung anschließend
▶ Insbesondere sinnvoll, wenn viele Daten ver- oder entschlüsselt werden sollen

- Schlüsselfahrplan wird einmalig berechnet und dann für alle Runden verwendet
- Vorteil: Schnelligkeit, da keine Berechnung während der Verschlüsselung notwendig ist
- Nachteil: Speicherverbrauch, da alle Unterschlüssel gespeichert werden müssen

Fließende Berechnung:
▶ On-The-Fly-Berechnung
▶ Der Unterschlüssel wird bei jeder Ver- und Entschlüsselung in jeder Runde neu
berechnet
▶ Rekursive Ableitung aus letztem Rundenschlüssel


Eingabe x: 128 Bit Blockgröße
Key k: 128 / 192 / 256 Bit --> Anzahl der internen Runden sind abhängig von der Länge des Schlüssels
--> Erzeugung von Unterschlüsseln aus dem Schlüssel
Key Whitening: Am Anfang und Ende der Verschlüsselung wird der Schlüssel mit dem Klartext auffadiert
Schlüssel werden rekursiv berechnet 

Schlüsselfahrpläne:
Wortorientierung -> 32 Bit pro Wort

Unterschlüssel in Matrix W abgelegt:
besteht aus Wörtern (4 Byte pro Wort)

Ausgabe y: 128 Bit Blockgröße

128 Bit Schlüssel: - 10 Runden
192 Bit Schlüssel: - 12 Runden
256 Bit Schlüssel: - 14 Runden


Diffusion: ShitfRows + MixColumns

Diff(A) + Diff(B) = Diff(A + B) -> lineare Diffusion

SHIFTROWS:
2. Zeile der Zustandmatrix wird zyklisch um 3 Byte nach rechts verschoben
3. Zeile der Zustandmatrix wird zyklisch um 2 Byte nach rechts verschoben
4. Zeile der Zustandmatrix wird zyklisch um 1 Byte nach rechts verschoben


MIXCOLUMUN-Transformation:


Funktion g:
→Rotation der Eingangsbytes, S-Box und Addition eines Rundenkoeffizienten
g macht den Fahrplan nicht-linear und stellt sicher, dass die Runden nicht symmetrisch sind
'''

# Beispiel für Rundenkoeffizienten
"""
rundenkoeffizienten (engl. round constants, Rcon) sind eine Liste von Konstanten, die im AES-Schlüsselfahrplan (Key Schedule) verwendet werden. 
Sie dienen dazu, bei der Erzeugung der Unterschlüssel für jede Runde eine zusätzliche Nichtlinearität einzuführen und sicherzustellen, dass die Rundenschlüssel nicht symmetrisch sind. 
Jeder Wert in der Liste entspricht dem Rundenkoeffizienten für eine bestimmte Runde und wird bei der Transformation der Schlüsselwörter (insbesondere in der Funktion g) addiert.
"""
#(a)
# Rundenkoeffizienten (Round Constants) für AES
# Werden in der Schlüsselerweiterung verwendet, um Nichtlinearität einzuführen
# 10 Runden da wir 128 Bit Schlüssel verwenden
rcon = [
    0x01000000, 0x02000000, 0x04000000,
    0x08000000, 0x10000000, 0x20000000,
    0x40000000, 0x80000000, 0x1b000000, 0x36000000
]


#(b) vollstände S-Box
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# g(z) mit x(7f 24 9f 86)_16 

x = 0x7f249f86 # 32 Bit Wort

"""
x << 8
Verschiebt alle Bits von x um 8 Stellen nach links. Die unteren 8 Bits werden mit Nullen aufgefüllt.

x >> 24
Verschiebt alle Bits von x um 24 Stellen nach rechts. Dadurch landen die oberen 8 Bits von x ganz rechts.

(x << 8) | (x >> 24)
Verbindet die beiden Ergebnisse mit einem bitweisen ODER. Das heißt: Die nach links verschobenen Bits werden mit den nach rechts verschobenen oberen 8 Bits kombiniert.
→ Das entspricht einer zyklischen Linksrotation (engl. "rotate left") um 8 Bits.

& 0xFFFFFFFF
Stellt sicher, dass das Ergebnis auf 32 Bits begrenzt bleibt.
"""
def rotate_word(word):
    # Rotiert die Eingabebytes um 8 Bit nach links
    return ((word << 8) | (word >> 24)) & 0xFFFFFFFF 

def substitute_word(word):
    # Ersetzt jedes Byte in einem 32-Bit-Wort durch das entsprechende Byte in der S-Box
    return ((s_box[(word >> 24) & 0xFF] << 24) |
            (s_box[(word >> 16) & 0xFF] << 16) |
            (s_box[(word >> 8) & 0xFF] << 8) |
            s_box[word & 0xFF])

def g_function(word, round):
    return substitute_word(rotate_word(word)) ^ rcon[round]

print(f"Original Word: {hex(x)}")
print(f"Rotated Word: {hex(rotate_word(x))}")
print(f"Substituted Word: {hex(substitute_word(rotate_word(x)))}")
print(f"g_function Output: {hex(g_function(x, 0))}")

print("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖")

# c) Implementieren Sie jetzt den gesamten Schlüsselplan
# k = Zustnandmatrix des Schlüssels
k = [
    0xe4, 0xa0, 0x70, 0x96,
    0x41, 0xc9, 0x28, 0xed,
    0xfd, 0x2b, 0x30, 0xf3,
    0x9d, 0x15, 0x22, 0x6c
    ]

def bytes_to_word(bytes_list):
    # Wandelt eine Liste von 4 Bytes in ein 32-Bit-Wort um
    return [(bytes_list[i] << 24) | (bytes_list[i+1] << 16) | (bytes_list[i+2] << 8) | bytes_list[i+3] for i in range(0, len(bytes_list), 4)]

def key_schedule(key) -> list:
    # Initialisiert den Schlüsselfahrplan mit dem Schlüssel
    word = bytes_to_word(key)
    n = len(word)  # Anzahl der 32-Bit-Wörter im Schlüssel
    r = 10  # Anzahl der Runden für AES-128

    # Füge Rundenkoeffizienten hinzu
    for i in range(n, (r + 1) * 4):
        temp = word[i - 1]
        if i % n == 0:
            temp = g_function(temp, i // n - 1)
        elif n > 6 and i % n == 4:
            temp = substitute_word(temp)
        word.append(word[i - n] ^ temp)

    return word
word = key_schedule(k)

# Letzter Rundenschlüssel = w[40] bis w[43] → als 4x4 Matrix darstellen (spaltenweise)
def words_to_matrix(words) -> list:
    # Wandelt eine Liste von 4 Wörtern in eine 4x4 Matrix um
    matrix = [[0] * 4 for _ in range(4)]
    for col in range(4):
        w = words[col]
        for row in range(4):
            matrix[row][col] = (w >> (24 - 8 * row)) & 0xFF
    return matrix

last_round_key_words = word[40:44]
last_round_matrix = words_to_matrix(last_round_key_words)

# Ausgabe der Matrix
print("Letzter Rundenschlüssel (Runde 10):")
for row in last_round_matrix:
    print(["{:02x}".format(b) for b in row])


print("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖")
""" (d) Sie finden folgende Zustände eines Schlüsselfahrplans vor:

Byte des Zustands der Runde n−1: (e7026fdf 56a6a100 c888c1d2 2532f4b9)16
Byte des Zustands der Runde n: (c0bd39e0 961b98e0 5e935932 7ba1ad8b)16
Geben Sie als Lösung dieser Teilaufgabe n, also die Runde zu der diese Zustände
gehören, an.
"""

previous_round = ['e7026fdf', '56a6a100', 'c888c1d2', '2532f4b9'] # Runde n-1
target_round = ['c0bd39e0', '961b98e0', '5e935932', '7ba1ad8b']    # Runde n

# Alle Rundenschlüssel in 4er-Gruppen ausgeben
print("Alle Rundenschlüssel (je 4 Wörter):")
for i in range(0, len(word), 4):
    group = word[i:i+4]
    print([f"{w:08x}" for w in group])
    if target_round == [f"{w:08x}" for w in group]:
        print(f"✅ Gefundene Runde n = {(i // 4) + 1}")
        break
print("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖")


def find_round(target_round, previous_round, key_schedule_words):
    # Konvertiere die gegebenen Hex-Strings in Integer-Werte (big-endian)
    prev_round_int = [int(x, 16) for x in previous_round]
    target_round_int = [int(x, 16) for x in target_round]
    
    # Durchsuche den Schlüsselfahrplan
    for i in range(0, len(key_schedule_words) - 7, 4):
        # Extrahiere 4 aufeinanderfolgende Wörter für Runde n-1 und n
        current_prev = key_schedule_words[i:i+4]
        current_next = key_schedule_words[i+4:i+8]
        
        # Prüfe auf Übereinstimmung (beachte Byte-Reihenfolge)
        if (current_prev == prev_round_int and 
            current_next == target_round_int):
            return (i // 4) + 1  # Rundenindex (1-basiert)
    
    # Debug-Ausgabe
    
    print("Gesuchte Runde n-1:", prev_round_int)
    print("Gesuchte Runde n:", target_round_int)
    print("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖")
    for i in range(0, len(key_schedule_words), 4):
        print(f"Runde {i//4}:", key_schedule_words[i:i+4])
        print("Hex:", [f"{w:08x}" for w in key_schedule_words[i:i+4]]) # Gibt w als 8-stellige, mit Nullen aufgefüllte, hexadezimale Zahl aus
        print("•••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••")
    
    return None  # Falls nicht gefunden


# Testaufruf
runde = find_round(target_round, previous_round, word)
if runde is not None:
    print(f"Die Zustände gehören zu Runde n = {runde}")
else:
    print("Die Zustände konnten keiner Runde zugeordnet werden.")
