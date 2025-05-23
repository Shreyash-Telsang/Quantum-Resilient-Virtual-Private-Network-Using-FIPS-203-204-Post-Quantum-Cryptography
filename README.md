# Quantum-Resilient Virtual Private Network Using FIPS 203-204 Post-Quantum Cryptography

## Overview
This project implements a Virtual Private Network (VPN) that is resilient to quantum attacks by leveraging post-quantum cryptography algorithms compliant with FIPS 203 and FIPS 204 standards. The goal is to provide secure communication channels that remain robust even in the era of quantum computing.

## Features
- **Quantum-Resilient Encryption:** Utilizes FIPS 203/204 post-quantum cryptographic algorithms for secure key exchange and data encryption.
- **Web Interface:** User-friendly web interface for VPN management and connection.
- **Python Backend:** Handles cryptographic operations, session management, and network tunneling.
- **Node.js Integration:** For web server and static asset management.
- **Cross-Platform:** Designed to work on major operating systems.

## Technologies Used
- **Python 3**
- **Flask** (for web backend)
- **Node.js** (for web interface and static files)
- **liboqs-python** (for post-quantum cryptography)
- **FIPS 203/204 algorithms**
- **HTML/CSS/JavaScript** (for frontend)

## Installation
### Prerequisites
- Python 3.8+
- Node.js (v14+ recommended)
- pip (Python package manager)
- git

### Clone the Repository
```sh
git clone https://github.com/Shreyash-Telsang/Quantum-Resilient-Virtual-Private-Network-Using-FIPS-203-204-Post-Quantum-Cryptography.git
cd Quantum-Resilient-Virtual-Private-Network-Using-FIPS-203-204-Post-Quantum-Cryptography
```

### Python Setup
1. (Optional) Create a virtual environment:
   ```sh
   python -m venv venv1
   source venv1/bin/activate  # On Windows: venv1\Scripts\activate
   ```
2. Install Python dependencies:
   ```sh
   pip install -r requirements.txt
   ```

### Node.js Setup
1. Install Node.js dependencies:
   ```sh
   npm install
   ```

## Usage
### Start the Backend Server
```sh
python serverweb4525.py
```

### Start the Web Interface (if applicable)
```sh
npm start
```

### Connect the Client
- Use the provided client script:
  ```sh
  python web_pqc_client.py
  ```
- Or use the web interface at `http://localhost:PORT` (replace PORT as configured).

## Project Structure
```
├── clientweb4525.py         # Python client for VPN
├── serverweb4525.py         # Python server for VPN
├── web_pqc_client.py        # Web client for PQC VPN
├── static/                  # Static web assets (JS, CSS)
├── templates/               # HTML templates
├── requirements.txt         # Python dependencies
├── package.json             # Node.js dependencies
├── liboqs-python/           # Post-quantum crypto library (submodule)
├── .gitignore
├── LICENSE
└── README.md
```

## Contribution Guidelines
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes with clear messages.
4. Submit a pull request describing your changes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact
For questions, suggestions, or collaboration, please contact:
- **Shreyash Telsang**  
  [GitHub](https://github.com/Shreyash-Telsang)

---
**Note:** For security reasons, implementation details of cryptographic primitives and key management are not disclosed in this README. Please refer to the official documentation of FIPS 203/204 and liboqs for more information on the cryptographic algorithms used.
