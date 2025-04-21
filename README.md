Copyright © 2025 Hubert Gaszow. All rights reserved.

This prototype Python tool is designed for academic research into RSA cryptographic vulnerabilities. It operates exclusively on RSA keys that it generates internally and is intended solely for controlled experimentation and educational analysis.
This code is designed for Linux and will not work on Windows without the /root directory.
The code is not intended, nor should it be used, for unauthorized attempts to break or compromise real-world RSA implementations.
Modification for such purposes is strictly discouraged.


How to use:\
With flask: python RSA_Analytics_snapshot.py --run-flask\
Without flask: python RSA_Analytics_snapshot.py\
Deep scan: python RSA_Analytics_snapshot.py --deep\
Quick scan:  python RSA_Analytics_snapshot.py --quick\
Entropy-only:  python RSA_Analytics_snapshot.py --entropy-only\
No visualisation: python RSA_Analytics_snapshot.py --no-visualization\
Using real world RSA certificate: python RSA_Analytics_snapshot.py --cert-path\
To save to a CSV file: python RSA_Analytics_snapshot.py --save-csv\
A path to RSA moduli: python RSA_Analytics_snapshot.py --key-file\
Threaded run: python RSA_Analytics_snapshot.py --threads\
If this does not work you may have to run it with python3, it will by default do a deep scan.\

