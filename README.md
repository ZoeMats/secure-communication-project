## Secure Communication – Practical Cryptography for Data Exchanges

A progressive, four-phase client-server communication system built in Python, demonstrating how encryption and authentication mechanisms can be layered to secure network communications. Each phase builds on the previous to achieve full confidentiality, integrity, authentication, and non-repudiation.

---

## 📋 Project Overview

This project implements a command-execution system where a **client** sends Linux shell commands to a **server** over a TCP socket, and the server returns the output. The system evolves across four phases, starting from plaintext communication and ending with hybrid encryption backed by digital signatures and X.509 certificates.

Network traffic was monitored at each phase using **Wireshark** to verify encryption effectiveness and compare performance.

---

## Project Structure

```
secure-communication-project/
├── PhaseOne/
│   ├── PhaseOne_server.py      # Plaintext server
│   └── PhaseOne_client.py      # Plaintext client
├── PhaseTwo/
│   ├── PhaseTwo_server.py      # RSA asymmetric encryption
│   └── PhaseTwo_client.py
├── PhaseThree/
│   ├── PhaseThree_server.py    # Hybrid encryption (RSA + AES)
│   └── PhaseThree_client.py
└── PhaseFour/
    ├── PhaseFour_server.py     # Hybrid encryption + digital signatures + X.509 certificates
    └── PhaseFour_client.py
```

---

## How to Run

### Prerequisites

```bash
pip install cryptography
```

Python 3.8+ is required. The scripts are designed to run on **Linux**.

---

### Phase 1 — Plaintext Communication

Both scripts should be in the same directory. The server writes its IP to `server_config.txt`, which the client reads.

```bash
# Terminal 1 – Start the server
python3 PhaseOne_server.py

# Terminal 2 – Start the client
python3 PhaseOne_client.py
```

---

### Phase 2 — Asymmetric Encryption (RSA)

The scripts use `os.getcwd()` to manage paths dynamically. A `SHARED/` folder is created for public keys and config, and `SERVER/` / `CLIENT/` for private keys.

```bash
# Terminal 1
python3 PhaseTwo_server.py

# Terminal 2
python3 PhaseTwo_client.py
```

---

### Phase 3 — Hybrid Encryption (RSA + AES)

Same usage as Phase 2. The client generates an AES session key, encrypts it with the server's RSA public key, and all subsequent communication uses AES-CBC.

```bash
# Terminal 1
python3 PhaseThree_server.py

# Terminal 2
python3 PhaseThree_client.py
```

---

### Phase 4 — Digital Signatures & X.509 Certificates

The server requires its IP address as a command-line parameter.

```bash
# Find your IP address
hostname -I

# Terminal 1 – Start the server with IP
python3 PhaseFour_server.py <server_IP>

# Terminal 2 – Start the client
python3 PhaseFour_client.py
```

If the IP address is not provided, the server terminal will display instructions on how to supply it.

---

## Client Commands

Once connected, you can type any Linux shell command (e.g. `whoami`, `ls`, `pwd`, `ip addr`).

| Command | Description |
|---|---|
| `help` | Show available commands |
| `clear` | Clear the terminal screen |
| `show-cert` | Display server certificate info (Phase 4 only) |
| `client-end` | Terminate the client connection |
| `server-end` | Shut down the server |

---

## Security Phases Explained

### Phase 1 – Plaintext
Client and server communicate in plain, unencrypted text over TCP sockets. All commands and responses are visible in Wireshark packet captures.

### Phase 2 – Asymmetric Encryption (RSA-2048)
Both parties generate RSA key pairs. Public keys are exchanged via a shared folder. Commands and responses are encrypted using OAEP padding with SHA-256. Large data is chunked to work around RSA size limits.

### Phase 3 – Hybrid Encryption (RSA + AES-256-CBC)
The client generates a random AES-256 key and IV, encrypts them using the server's RSA public key, and sends them securely. All subsequent communication uses AES-CBC — faster and more efficient for continuous data exchange.

### Phase 4 – Digital Signatures & X.509 Certificates
Both parties generate self-signed X.509 certificates containing their public keys. Certificates are exchanged and verified before communication begins. Every message is signed using RSA-PSS (SHA-256) to guarantee:
- **Authentication** – verified identity of sender
- **Integrity** – message has not been tampered with
- **Non-repudiation** – sender cannot deny having sent the message

---

##  Key Management

| Phase | Keys Generated |
|---|---|
| Phase 2 | Server RSA key pair → `SERVER/`, public key → `SHARED/` |
| Phase 3 | Server RSA key pair + Client RSA key pair |
| Phase 4 | Server RSA + self-signed cert (`sc1`), Client RSA + self-signed cert (`sc2`) |

Private keys are stored locally and never shared. Public keys and certificates are placed in the `SHARED/` folder.

---

## Technical Details

- **Language**: Python 3
- **Library**: [`cryptography`](https://cryptography.io/)
- **Encryption**: RSA-2048 (OAEP/PSS), AES-256-CBC
- **Certificates**: Self-signed X.509 (valid 365 days), SHA-256 signature
- **Socket**: TCP, port `9222`
- **Concurrency**: Multi-threaded server with mutex locks (`threading.Lock`) for safe shared resource access
- **OS**: Linux (VMware Workstation Pro)

---

## Wireshark Observations (Summary)

| Phase | Encryption | Wireshark Readable? | Transmission Rate |
|---|---|---|---|
| Phase 1 | None | YES – fully visible | ~8 seconds / 6 commands |
| Phase 2 | RSA only | NO | ~9 seconds / 6 commands |
| Phase 3 | RSA + AES | NO | ~13 seconds (more consistent) |
| Phase 4 | RSA + AES + Sigs/Certs | NO | **16 packets/sec**, ~3 seconds |

Phase 4 shows that while certificates introduce some initial overhead, they enable significantly faster sustained transmission.

---

## Possible Enhancements

- **Elliptic Curve Cryptography (ECC)** – same security as RSA with smaller keys and better performance
- **Username/password authentication** – additional layer beyond certificate verification
- **Certificate Authority (CA)** – replace self-signed certs with a proper CA chain for stronger trust
- **TLS integration** – replace manual handshake with standard TLS/SSL

---

## License

This project was developed for educational purposes as part of a practical cryptography module.****
