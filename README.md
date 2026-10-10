# Quantum-readiness-website-scanner
Python tool that checks whether websites are protected against 'harvest now, decrypt later' quantum attacks. It hand-builds a raw TLS 1.3 handshake offering NIST's post-quantum ML-KEM hybrid alongside classical key exchange, then reads which one the server picks. Scans UK banks, fintechs and public-sector sites and exports results to CSV.
