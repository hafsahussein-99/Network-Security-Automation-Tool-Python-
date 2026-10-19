# Network Security Automation Tool

A clean, high-performance, multi-threaded network reconnaissance tool written natively in Python. This utility automates host resolution, audits critical communication ports, extracts active banners, and cross-references discovered ports against common security exploit vectors.

## Technical Capabilities & Features
* **Multi-Threaded Execution:** Utilizes Python's `concurrent.futures` workflow engine to run parallel connection threads, improving host mapping speed by over 60%.
* **Input Sanitization:** Features built-in Exception and Domain Resolution (`socket.gaierror`) handling routines to manage broken arguments or unreachable nodes cleanly.
* **Banner-Grabbing Operations:** Collects raw target interaction payloads to expose active protocol versions, aiding developers during defensive security audits.

## Getting Started

### Prerequisites
* Python 3.x environment installed.
* Standard system network dependencies (`socket`, `sys`, `concurrent.futures`, `datetime`).

### Deployment Instructions
1. Clone the project locally:
   ```bash
   git clone https://github.com
   cd python-port-scanner
   ```
2. Execute the python pipeline tool:
   ```bash
   python scanner.py
   ```
3. Input an active development target (e.g., `127.0.0.1` or local virtual sandbox nodes) to parse active connection channels.
