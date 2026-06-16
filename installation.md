# Guida all'Installazione di TorCall

Questa guida ti accompagna passo passo dall'ambiente vuoto fino alla prima
chiamata vocale cifrata over Tor. È pensata per **Windows**, piattaforma su cui
TorCall è sviluppato e che include il binario `tor.exe`.

---

## 1. Prerequisiti

Prima di iniziare assicurati di avere:

- **Python 3.11** (o versione compatibile 3.10+). Verifica con:
  ```powershell
  python --version
  ```
  Se il comando non viene riconosciuto, installa Python da
  [python.org](https://www.python.org/downloads/) e durante l'installazione
  spunta **"Add Python to PATH"**.

- **Un microfono e altoparlanti/cuffie** funzionanti (TorCall usa
  `sounddevice` per accedere alle periferiche audio).

- **Connessione a Internet** per scaricare le dipendenze e i binari di Tor.

- **~150 MB di spazio libero** (Tor Expert Bundle + dipendenze Python).

> 💡 Su Windows tutti i comandi di questa guida vanno eseguiti in
> **PowerShell**. Concatena i comandi con `;`, non con `&&`.

---

## 2. Ottenere il Codice

Posizionati nella cartella del progetto. Se hai clonato il repository:

```powershell
cd C:\percorso\verso\TorCall
```

La struttura attesa contiene `main.py`, `requirements.txt` e la cartella
`torcall/`.

---

## 3. Creare e Attivare l'Ambiente Virtuale

Un ambiente virtuale isola le dipendenze di TorCall dal resto del sistema.

```powershell
# Crea l'ambiente virtuale nella cartella .venv
python -m venv .venv

# Attiva l'ambiente
.venv\Scripts\activate
```

Se PowerShell blocca l'attivazione con un errore di execution policy, sbloccala
solo per la sessione corrente e riprova:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.venv\Scripts\activate
```

A questo punto il prompt mostra il prefisso `(.venv)`.

---

## 4. Installare le Dipendenze Python

Con l'ambiente attivo, installa i pacchetti richiesti:

```powershell
pip install -r requirements.txt
```

Questo installa:

| Pacchetto      | A cosa serve                                             |
| -------------- | -------------------------------------------------------- |
| `PySide6`      | Interfaccia grafica (Qt)                                 |
| `sounddevice`  | Acquisizione microfono e riproduzione audio              |
| `numpy`        | Elaborazione dei campioni audio                          |
| `opuslib`      | Codec Opus (richiede la DLL nativa, vedi passo 6)        |
| `stem`         | Controllo del processo Tor e degli hidden service        |
| `cryptography` | X25519/Ed25519, AES-256-GCM, HKDF, scrypt                |
| `PySocks`      | Connessioni outbound tramite proxy SOCKS5 di Tor         |

---

## 5. Scaricare i Binari di Tor

TorCall avvia un proprio processo Tor a partire da `tor.exe`. Scaricalo ed
estrailo automaticamente con lo script incluso:

```powershell
python scratch/download_tor.py
```

Al termine troverai `tor.exe` nella cartella `tor/`. Questo passo è
**obbligatorio**: senza il binario di Tor l'app non può creare l'hidden service
né instradare le chiamate.

---

## 6. Installare il Codec Opus (consigliato)

`opuslib` ha bisogno di una libreria nativa Opus a runtime, non inclusa nel
pacchetto Python. Senza di essa TorCall **funziona comunque**, ma ripiega su
audio PCM non compresso (≈16× la banda — praticamente inutilizzabile su Tor).

Scarica e installa la DLL automaticamente:

```powershell
python scratch/download_opus.py
```

Lo script scarica la build ufficiale di libopus, ne verifica lo SHA-256 ed
estrae la DLL nella cartella `lib/` del progetto come `opus.dll`. All'avvio
vedrai nei log una riga simile a:

```
Opus library located: ...\TorCall\lib\opus.dll
```

> Se preferisci, puoi anche copiare manualmente una DLL chiamata `opus.dll`
> (oppure `libopus-0.dll` / `libopus.dll`) nella cartella `lib/`.

---

## 7. (Opzionale) Eseguire i Test

Per verificare che tutto sia a posto prima del primo avvio:

```powershell
pip install pytest
python -m pytest tests/ -q
```

Dovresti vedere tutti i test verdi (al momento **69 passed**).

---

## 8. Avviare l'Applicazione

```powershell
python main.py
```

Al primo avvio TorCall:

1. Avvia il processo Tor in background (il bootstrap può richiedere qualche
   decina di secondi).
2. Crea un **hidden service** e genera il tuo indirizzo `.onion` effimero.
3. Mostra la finestra principale con il tuo indirizzo, pronto per chiamare o
   ricevere chiamate.

> ⏳ Il primo bootstrap di Tor è il passaggio più lento. Attendi che lo stato
> indichi che Tor è pronto prima di effettuare una chiamata.

---

## 9. Effettuare la Prima Chiamata

1. **Condividi il tuo indirizzo `.onion`** con l'altra persona (tramite un
   canale sicuro). Usa il pulsante di copia accanto all'indirizzo.
2. **Incolla l'indirizzo del contatto** nel campo di chiamata e avvia la
   chiamata.
3. Quando la connessione si stabilisce, entrambi vedete una **Short
   Authentication String (SAS)** di 4 parole sotto "Verify aloud".
4. **Leggete le parole a voce a vicenda**: se coincidono su entrambi i lati la
   chiamata è autentica end-to-end. Se **non** coincidono, qualcuno potrebbe
   intercettare la chiamata (man-in-the-middle): riagganciate.

Sotto la SAS compare anche lo stato dell'identità del contatto:

- `🔑 New contact pinned` — primo contatto, identità appena fissata.
- `✓ Known contact` — l'identità coincide con quella già fissata.
- `⚠ IDENTITÀ CAMBIATA` — l'identità è diversa dall'attesa: possibile MITM o
  rotazione di chiavi, da verificare prima di fidarsi.

---

## 10. La Rubrica

I contatti con cui hai parlato vengono fissati (TOFU) e sono consultabili nella
rubrica, da cui puoi:

- **Rinominare** un contatto con un nome leggibile.
- **Copiare** il suo indirizzo per richiamarlo.
- **Rimuovere** un contatto. La rimozione cancella *tutti* gli indirizzi
  `.onion` legati alla stessa identità (utile se il contatto ha cambiato
  indirizzo mantenendo la chiave) ed è protetta da una conferma esplicita.

---

## 11. Configurazione tramite Variabili d'Ambiente (opzionale)

TorCall funziona senza configurazione, ma alcune variabili d'ambiente
rafforzano privacy e sicurezza. Impostale **prima** di lanciare `python main.py`
nella stessa sessione PowerShell.

```powershell
# Cifra a riposo (at-rest) identità hidden service, identità Ed25519 e contatti
# con scrypt + AES-256-GCM. Fortemente consigliata.
$env:TORCALL_PASSPHRASE = "una-passphrase-robusta"

# Richiede la conferma manuale delle parole SAS prima di abilitare l'audio
# (anti-MITM: nessun audio passa finché entrambi non confermano). Default: off.
$env:TORCALL_REQUIRE_SAS = "1"

# Tentativi automatici di riconnessione lato chiamante se la connessione cade
# durante la chiamata. Default 3; 0 disabilita la riconnessione.
$env:TORCALL_RECONNECT_ATTEMPTS = "3"

# Disattiva la cadenza costante (risparmia banda, riduce la privacy temporale).
$env:TORCALL_CONSTANT_RATE = "0"

# Abilita il logging su file (disattivo di default).
$env:TORCALL_LOG_FILE = "1"

# Porte Tor alternative, se hai già un Tor di sistema sulle porte standard.
$env:TORCALL_SOCKS_PORT = "9150"
$env:TORCALL_CONTROL_PORT = "9151"

python main.py
```

> ⚠️ **Importante**: senza `TORCALL_PASSPHRASE` i segreti vengono salvati in
> chiaro su disco (con un warning nei log), affidandosi solo ai permessi file
> del sistema operativo. Imposta una passphrase per cifrarli a riposo.

I dati persistenti (identità, contatti, dati di Tor, log) vengono salvati in
`%APPDATA%\TorCall\` su Windows.

---

## 12. Risoluzione dei Problemi

**L'attivazione del venv viene bloccata**
Esegui `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` e
riprova `.venv\Scripts\activate`.

**`tor.exe` non trovato / Tor non parte**
Riesegui `python scratch/download_tor.py` e verifica che esista `tor/tor.exe`.

**L'audio usa molta banda / qualità scadente**
Manca la DLL di Opus: l'app sta usando PCM non compresso. Esegui
`python scratch/download_opus.py` e controlla nei log la riga
`Opus library located: ...`.

**Conflitto sulle porte Tor**
Se hai già un Tor di sistema attivo, imposta `TORCALL_SOCKS_PORT` e
`TORCALL_CONTROL_PORT` su porte libere (vedi passo 11). I default di TorCall
sono `9150`/`9151`.

**Il bootstrap di Tor è lento o non completa**
Il primo avvio può richiedere tempo. Se la rete blocca Tor, potrebbe servire un
pluggable transport (configurazione avanzata non coperta da questa guida).

**Nessun microfono rilevato**
Verifica che il microfono sia collegato e abilitato nelle impostazioni del
sistema operativo, poi riavvia l'app.

---

## Riepilogo Comandi (Quick Start)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scratch/download_tor.py
python scratch/download_opus.py
python main.py
```
