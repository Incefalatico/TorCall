# TorCall — Chiamate Vocali Cifrate over Tor

TorCall è un'applicazione desktop moderna, sicura e peer-to-peer per effettuare chiamate vocali cifrate tramite la rete **Tor**, sviluppata in **Python 3.11**, **PySide6 (Qt)** e **Tor Hidden Services**.

Consente agli utenti di chiamarsi in modo anonimo scambiando semplicemente indirizzi `.onion` effimeri.

---

## 🔒 Caratteristiche di Sicurezza e Design

* **Anonimato**: Tutte le connessioni sono instradate attraverso la rete Tor. La posizione e l'indirizzo IP del chiamante e del ricevente sono nascosti utilizzando l'onion routing di Tor.
* **Cifratura End-to-End (E2EE)**:
  * **Scambio di Chiavi**: Coppia di chiavi effimere **X25519** (ECDH) generata per ogni singola chiamata.
  * **Derivazione della Chiave**: Dal segreto ECDH si derivano via **HKDF-SHA256** **due chiavi direzionali** distinte (una per il flusso chiamante→ricevente, una per ricevente→chiamante). Usare chiavi separate per le due direzioni evita il riuso del nonce AES-GCM, dato che entrambi i peer iniziano il proprio contatore di pacchetti da 0.
  * **Cifratura**: I flussi audio sono cifrati pacchetto per pacchetto tramite **AES-256-GCM** con un nonce univoco a 12 byte (strutturato come un contatore sequenziale monotonic big-endian a 8 byte imbottito con zeri).
  * **Anti-replay**: Il ricevente tiene traccia dell'ultima sequenza audio accettata e scarta i pacchetti duplicati o fuori ordine; il contatore avanza solo dopo una decifratura autenticata con successo.
  * **Verifica anti-MITM (SAS)**: Lo scambio X25519 effimero protegge dagli intercettatori passivi ma non da un man-in-the-middle attivo che inoltri l'handshake. All'inizio di ogni chiamata l'app mostra una **Short Authentication String** (4 parole) derivata dalle chiavi pubbliche di entrambi i peer: i due interlocutori la confrontano a voce e, se non coincide, la chiamata è compromessa e va chiusa.
* **Identità persistente e riconoscimento dei contatti**:
  * **Identità a lungo termine Ed25519**: oltre alle chiavi effimere per-chiamata, ogni installazione genera una coppia di chiavi **Ed25519** persistente. A ogni handshake la chiave effimera X25519 viene **firmata** con l'identità a lungo termine, così il peer può verificare che chi controlla l'indirizzo `.onion` controlla anche l'identità riconosciuta.
  * **Pinning dei contatti (Trust-On-First-Use)**: alla prima chiamata verso un indirizzo l'identità del peer viene **fissata** (pinned). Se in una chiamata successiva l'identità associata a quell'indirizzo cambia, l'app mostra un avviso `⚠ IDENTITÀ CAMBIATA` — esattamente come fa SSH con le host key — segnalando un possibile MITM o una rotazione di identità da verificare.
  * **Fingerprint leggibile**: ogni identità è riassunta in un fingerprint esadecimale a gruppi (es. `a1:b2:c3:…`) mostrato in chiamata.
  * **Rubrica**: i contatti fissati sono consultabili in una rubrica da cui è possibile **rinominarli**, copiarne l'indirizzo per richiamarli, oppure **rimuoverli**. La rimozione cancella ogni indirizzo `.onion` legato alla stessa identità (utile se il contatto ha ruotato indirizzo mantenendo la chiave) ed è protetta da una conferma esplicita.
* **Protezione dei segreti a riposo (at-rest)**:
  * **Cifratura con passphrase**: l'identità dell'hidden service, l'identità Ed25519 e il database dei contatti sono cifrati su disco con **scrypt** (stretching della passphrase) + **AES-256-GCM** quando è impostata la variabile d'ambiente `TORCALL_PASSPHRASE`. In assenza di passphrase si ricade su archiviazione in chiaro con un warning (per retrocompatibilità), affidandosi ai permessi file del sistema operativo.
  * **Igiene della memoria**: le chiavi di sessione e le chiavi private effimere sono tenute in `bytearray` mutabili e **azzerate** a fine chiamata, per ridurre la persistenza dei segreti in memoria.
* **Resistenza all'analisi del traffico**:
  * **Padding a blocchi**: ogni frame audio cifrato viene imbottito fino a un multiplo di `TRAFFIC_PAD_BLOCK` (256 byte) prima della cifratura, così tutte le dimensioni dei pacchetti collassano su pochi valori fissi. Questo nasconde il segnale a bitrate variabile (VBR) di Opus, che altrimenti rivelerebbe *quando* qualcuno sta parlando anche se il contenuto è cifrato.
  * **Cadenza costante**: in modalità `CONSTANT_RATE_SEND` (attiva di default) i pacchetti audio vengono trasmessi a ritmo fisso (un frame ogni 20 ms) e nei momenti di silenzio vengono inviati **frame di silenzio**, così un osservatore non può dedurre i tempi del parlato dalla tempistica dei pacchetti. Disattivabile con `TORCALL_CONSTANT_RATE=0` per risparmiare banda a scapito della privacy temporale.
* **Igiene dei log**:
  * I log vanno **solo su console** di default (il logging su file è opt-in via `TORCALL_LOG_FILE=1`) e un filtro automatico **oscura** indirizzi `.onion`, service id e indirizzi IPv4/IPv6 dai messaggi, evitando che dati sensibili finiscano accidentalmente nei log.
* **Gestione Audio**:
  * Acquisizione da microfono e riproduzione in tempo reale tramite la libreria `sounddevice` in esecuzione su thread secondari dedicati.
  * Coda **Jitter Buffer** adattiva: pre-bufferizza fino a una profondità *target* prima di rilasciare l'audio, alza il target quando gli underrun si ripetono e lo riabbassa con cautela quando il collegamento è stabile, per assorbire le fluttuazioni di latenza su Tor mantenendo la latenza più bassa possibile.
  * Compressione audio tramite codec **Opus** (con fallback automatico a PCM non compresso in caso di assenza della libreria nativa DLL).
* **Esperienza Utente**:
  * Interfaccia scura (Dark Theme) moderna ed elegante in QSS (CSS per Qt) con accenti viola in stile Tor e layout in glassmorphism.
  * Microfono sempre attivo durante la chiamata con un pulsante rapido per attivare/disattivare il muto.
  * Suoneria audio generata proceduralmente riprodotta durante gli avvisi di chiamata in arrivo.
  * Funzione per copiare l'indirizzo negli appunti con un clic e rigenerazione automatica degli indirizzi hidden service effimeri.

---

## 🏗️ Architettura del Progetto

```
TorCall/
├── main.py                    # Entry point dell'applicazione
├── requirements.txt           # Dipendenze dei pacchetti Python
├── README.md                  # Documentazione del progetto (questo file)
│
├── tor/                       # Binari estratti di Tor Expert Bundle
│   └── tor.exe
│
├── torcall/
│   ├── __init__.py
│   ├── app.py                 # Inizializzazione e coordinamento dei sottosistemi
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── audio_engine.py    # Gestione microfono/altoparlanti e codec Opus
│   │   ├── crypto.py          # X25519/Ed25519, AES-GCM, at-rest, padding, SAS
│   │   ├── identity.py        # Identità Ed25519 persistente + pinning contatti (TOFU)
│   │   ├── tor_manager.py     # Controllo processo Tor e registrazione hidden service
│   │   └── call_manager.py    # Macchina a stati (Idle, Dialing, Ringing, InCall)
│   │
│   ├── network/
│   │   ├── __init__.py
│   │   ├── protocol.py        # Protocollo binario di segnalazione e pacchetti audio
│   │   ├── server.py          # Server TCP in ascolto sulla porta locale hidden service
│   │   └── client.py          # Connettore outbound SOCKS5 tramite proxy SOCKS Tor
│   │
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── main_window.py     # Finestra principale ed emettitore di suoneria
│   │   ├── call_widget.py     # Interfaccia durante la chiamata (Timer, Mute, Volume)
│   │   └── styles.py          # Foglio di stile QSS personalizzato
│   │
│   └── utils/
│       ├── __init__.py
│       ├── config.py          # Configurazione globale e costanti dell'applicazione
│       └── logger.py          # Registrazione log su console e file in modo thread-safe
│
├── tests/
│   ├── test_audio.py          # Test per jitter buffer e codifica/decodifica Opus
│   ├── test_crypto.py         # Test crypto: ECDH, AES-GCM, at-rest, Ed25519, padding
│   ├── test_identity.py       # Test identità persistente e pinning contatti (TOFU)
│   ├── test_logger.py         # Test scrubbing .onion/IP dai log
│   └── test_protocol.py       # Test serializzazione pacchetti e handshake firmato
│
└── scratch/                   # Script di utilità e verifica
    ├── find_tor.py            # Script per trovare le directory di rilascio di Tor
    ├── download_tor.py        # Download automatico di Tor Expert Bundle
    └── test_tor_bootstrap.py  # Script per testare manualmente il bootstrap di Tor
```

---

## 🛠️ Correzioni e Miglioramenti Principali

### Sicurezza

1. **Chiavi direzionali (fix riuso nonce AES-GCM)**:
   - In precedenza entrambi i peer derivavano la *stessa* chiave e ripartivano dal contatore `seq=0`, riusando quindi la coppia chiave+nonce per il primo pacchetto di ciascun lato — condizione catastrofica per AES-GCM. Ora `crypto.derive_session_keys()` espande il segreto ECDH con HKDF a 64 byte e lo divide in una chiave `chiamante→ricevente` e una `ricevente→chiamante`, così i due flussi non condividono mai lo spazio dei nonce.
2. **Server in ascolto solo su loopback**:
   - `server.py` ora effettua il bind su `127.0.0.1` invece di `0.0.0.0`. Dato che l'hidden service inoltra la sua porta remota verso quella locale, ascoltare su tutte le interfacce esponeva la porta della chiamata alla LAN, permettendo connessioni che bypassavano Tor.
3. **Protezione anti-replay**:
   - Il `CallManager` traccia l'ultima sequenza audio accettata e scarta pacchetti duplicati o fuori ordine. Il contatore avanza solo dopo una decifratura autenticata, così una sequenza falsificata non può avvelenare la finestra anti-replay.
4. **Verifica anti-MITM (SAS)**:
   - All'inizio della chiamata viene mostrata una Short Authentication String di 4 parole, derivata dalle chiavi pubbliche di entrambi i peer e indipendente dal ruolo, da confrontare a voce per smascherare un man-in-the-middle attivo.
5. **Serializzazione degli invii sul socket**:
   - Tutti i `sendall` (audio, ping, ACK) passano da un unico helper protetto da lock, evitando che scritture concorrenti da thread diversi interlaccino i byte e corrompano il framing dei pacchetti.

### Privacy e anonimato

13. **Identità persistente Ed25519 + handshake firmato con nonce anti-replay**:
    - Ogni installazione ha una chiave d'identità a lungo termine Ed25519 che firma la chiave effimera X25519 a ogni chiamata. Il peer verifica la firma e può riconoscere la stessa identità tra chiamate diverse, indipendentemente dall'indirizzo `.onion`.
    - L'handshake v2 include un **nonce di 16 byte** (timestamp 8 byte + 8 byte casuali) coperto dalla firma: il ricevente rifiuta firme con nonce scaduto (oltre ±120 s) o manomesso, impedendo il replay di un vecchio handshake. Le firme v1 e v2 non sono intercambiabili.
14. **Pinning dei contatti (TOFU)**:
    - L'identità di un contatto viene fissata al primo contatto e confrontata nelle chiamate successive. Un cambio d'identità per lo stesso indirizzo genera un avviso visibile (`⚠ IDENTITÀ CAMBIATA`), come le host key di SSH.
15. **Segreti cifrati a riposo**:
    - Identità hidden service, identità Ed25519 e database contatti sono cifrati con scrypt + AES-256-GCM quando è impostata `TORCALL_PASSPHRASE`. Il formato corrente è auto-descrittivo (magic `TCV2`, con il parametro di costo scrypt `log2(N)` scritto nell'header e autenticato come associated data), con rilevamento automatico e lettura retrocompatibile dei vecchi blob `TCV1` e dei file legacy in chiaro.
16. **Igiene della memoria**:
    - Le chiavi di sessione e private effimere sono `bytearray` azzerati a fine chiamata, riducendo la persistenza dei segreti in RAM.
17. **Resistenza all'analisi del traffico**:
    - Padding dei frame audio a blocchi di 256 byte (nasconde il segnale VBR di Opus) e invio a cadenza costante con frame di silenzio (nasconde i tempi del parlato).
18. **Igiene dei log**:
    - Log solo su console di default (file opt-in via `TORCALL_LOG_FILE`) con oscuramento automatico di indirizzi `.onion`, service id e IP dai messaggi.

### Affidabilità e correttezza

6. **Pipeline di invio fuori dal thread UI**:
   - Codifica Opus, cifratura e invio (potenzialmente bloccante su Tor) sono stati spostati dal thread della GUI a un thread dedicato alimentato da una coda limitata, eliminando i blocchi dell'interfaccia ogni 20 ms.
7. **Watchdog di keep-alive effettivo**:
   - `PING_TIMEOUT_S` ora è realmente applicato: se non arriva traffico dal peer entro la soglia, la chiamata viene chiusa anche quando `sendall` sembra ancora funzionare, rilevando le morti silenziose del peer.
8. **Slot e Threading di TorManager**:
   - I metodi del worker in background (`start_tor`, `regenerate_address`, `load_identity`) in `tor_manager.py` sono stati decorati con `@Slot()` di PySide6. Questo ha risolto i problemi di comunicazione tra thread, consentendo a `QMetaObject.invokeMethod` di trovarli ed eseguirli correttamente tramite connessione in coda (`QueuedConnection`). L'indirizzo `.onion` è ora protetto da lock per l'accesso cross-thread.
9. **Correzione API di avvio Tor**:
   - Sostituito `stem.process.launch_tor` con `stem.process.launch_tor_with_config`. La funzione precedente generava un `TypeError` perché non accettava dizionari di configurazione personalizzati.
10. **Fallback del Codec Opus**:
    - Modificato `audio_engine.py` per catturare qualsiasi `Exception` generica (non solo `ImportError`) all'importazione di `opuslib`. Su Windows, `opuslib` viene importata correttamente ma genera un'eccezione se la DLL nativa `libopus.dll` non è installata nel sistema. Ora l'app ripiega automaticamente (fallback) sullo streaming PCM non compresso, evitando crash.
11. **Risoluzione DNS SOCKS5**:
    - Configurato il socket SOCKS5 in `client.py` con `rdns=True` (Remote DNS resolution) in modo che i nomi `.onion` remoti siano risolti in sicurezza dal proxy Tor, prevenendo perdite accidentali di DNS locali (DNS leaks).
12. **Porte Tor configurabili**:
    - Le porte SOCKS e Control sono ora sovrascrivibili tramite le variabili d'ambiente `TORCALL_SOCKS_PORT` e `TORCALL_CONTROL_PORT` (default `9150`/`9151`), per non entrare in conflitto con un Tor di sistema già attivo sulle porte standard `9050`/`9051`.

---

## 🚀 Guida all'Uso

### 1. Preparazione dell'Ambiente
Crea un ambiente virtuale Python e installa le dipendenze richieste:
```powershell
# Crea l'ambiente virtuale
python -m venv .venv

# Attiva l'ambiente virtuale
.venv\Scripts\activate

# Installa i requisiti
pip install -r requirements.txt
```

### 2. Download dei Binari Tor
Esegui lo script per scaricare ed estrarre automaticamente Tor Expert Bundle per Windows nella cartella di progetto:
```powershell
python scratch/download_tor.py
```
Questo estrarrà il file `tor.exe` all'interno della directory `tor/`.

### 3. Esegui i Test Unitari
Assicurati che la libreria di test `pytest` sia installata ed esegui la suite di test automatizzata:
```powershell
pip install pytest
python -m pytest tests/ -v
```

### 4. Avvia l'Applicazione
Lancia TorCall:
```powershell
python main.py
```

> **Porte Tor personalizzate (opzionale)** — Se hai già un Tor di sistema in esecuzione sulle porte standard, imposta porte alternative prima di avviare:
> ```powershell
> $env:TORCALL_SOCKS_PORT = "9150"
> $env:TORCALL_CONTROL_PORT = "9151"
> python main.py
> ```

### 5. Verifica l'Identità della Chiamata (SAS)
Appena la chiamata si stabilisce, entrambe le parti vedono una stringa di **4 parole** (Short Authentication String) sotto la voce "Verify aloud". Leggetela a voce a vicenda: se le parole coincidono su entrambi i lati la connessione è autentica end-to-end; se **non** coincidono, qualcuno potrebbe intercettare la chiamata (man-in-the-middle) e conviene riagganciare.

Sotto la SAS l'app mostra anche lo **stato dell'identità** del contatto:
- `🔑 New contact pinned` — primo contatto con quell'indirizzo, identità appena fissata.
- `✓ Known contact` — l'identità coincide con quella fissata in precedenza.
- `⚠ IDENTITÀ CAMBIATA` — l'identità è diversa da quella attesa: possibile MITM o rotazione di chiavi, da verificare prima di fidarsi.

### 6. Variabili d'Ambiente per Privacy (opzionale)
TorCall funziona senza configurazione, ma alcune variabili d'ambiente rafforzano la privacy:

```powershell
# Cifra a riposo identità hidden service, identità Ed25519 e contatti
$env:TORCALL_PASSPHRASE = "una-passphrase-robusta"

# Disattiva la cadenza costante (risparmia banda, riduce la privacy temporale)
$env:TORCALL_CONSTANT_RATE = "0"

# Abilita il logging su file (disattivo di default)
$env:TORCALL_LOG_FILE = "1"

# Richiede la conferma manuale delle parole SAS prima di abilitare l'audio
# (anti-MITM: nessun audio passa finché entrambi non confermano). Disattivo di default.
$env:TORCALL_REQUIRE_SAS = "1"

# Numero di tentativi automatici di riconnessione lato chiamante se la
# connessione cade durante la chiamata (default 3; 0 disabilita la riconnessione).
$env:TORCALL_RECONNECT_ATTEMPTS = "3"

python main.py
```

> ⚠️ **Importante**: senza `TORCALL_PASSPHRASE` i segreti vengono salvati in chiaro su disco (con un warning nei log), affidandosi solo ai permessi file del sistema operativo. Imposta una passphrase per cifrarli a riposo.

---

## 📋 Dettagli Protocollo di Segnalazione e Dati

TorCall comunica attraverso un protocollo binario personalizzato leggero. Ogni pacchetto è composto da un **header fisso di 7 byte** seguito da un payload di lunghezza variabile:

```
┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ Tipo Messaggio   │ Numero Sequenza  │ Lunghezza        │ Payload ...      │
│ (1 Byte)         │ (4 Byte)         │ Payload (2 Byte) │                  │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

### Messaggi del Protocollo
- **`CALL_REQUEST` (0x01)**: Inizio handshake. Il payload è un *handshake firmato*. Nel formato corrente (v2, **144 byte**): chiave pubblica X25519 effimera (32 byte) + identità pubblica Ed25519 (32 byte) + firma Ed25519 (64 byte) + nonce anti-replay (16 byte). La firma copre nonce + chiave effimera. Sono accettati anche il formato v1 a 128 byte (senza nonce) e quello legacy a 32 byte (sola chiave effimera, senza identità) per retrocompatibilità.
- **`CALL_ACCEPT` (0x02)**: Risposta positiva alla chiamata. Stesso formato handshake firmato del `CALL_REQUEST`.
- **`CALL_REJECT` (0x03)**: Rifiuto della chiamata (o segnale di occupato se il ricevente è già in un'altra chiamata).
- **`AUDIO_DATA` (0x10)**: Pacchetto audio cifrato in tempo reale. Il payload è strutturato come `[Nonce GCM da 12B] + [Testo cifrato AES-GCM]`. Il testo in chiaro cifrato è un frame Opus *imbottito* (prefisso di lunghezza a 2 byte + dati + padding a zero fino a un multiplo di 256 byte) per resistere all'analisi del traffico.
- **`CALL_END` (0x20)**: Segnale di fine chiamata (riaggancio).
- **`CALL_END_ACK` (0x21)**: Conferma della fine della chiamata.
- **`PING` (0x30) / `PONG` (0x31)**: Pacchetti di keep-alive inviati ogni 15 secondi per mantenere attivi i circuiti TCP della rete Tor.
