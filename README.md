# Secure Online Storage System

## Overview

This project implements a secure online storage system as part of the COMP3334 course, designed to provide users with a robust platform for uploading, accessing, and managing files securely. The system consists of two sub-programs: a **Client** for user interactions and a **Server** for managing user data and files. It addresses security concerns such as passive adversaries on the server and unauthorized users attempting to access legitimate users' files.

The system implements all core functionalities specified in the project requirements, including user management, data encryption, access control, and log auditing, along with an extended functionality: **One-Time Password (OTP)** for multi-factor authentication (MFA).

### Components
- **Client**: Handles file uploads/downloads, encryption/decryption, and user interactions via a command-line menu.
- **Server**: Manages user accounts, stores encrypted files, and maintains activity logs, using SQLite for data storage.

### Core Functionalities
- **User Management**: Register users with unique usernames (email addresses) and hashed passwords, login verification, and password reset.
- **Data Encryption**: Encrypts files on the client side before upload and decrypts them on download, ensuring the server cannot read plaintext.
- **Access Control**: Restricts file access to owners and designated users for sharing, preventing unauthorized access.
- **Log Auditing**: Records critical operations (e.g., login, logout, upload, delete, share) for non-repudiation, accessible by an administrator.
- **General Security**: Validates filenames to prevent attacks (e.g., path traversal) and protects against SQL injection.

### Extended Functionality
- **Multi-Factor Authentication (OTP)**: Implements OTP sent via email for enhanced login security.

## Features
- **Secure File Storage**: Client-side encryption ensures data privacy.
- **User Authentication**: Supports registration, login, and password reset with OTP-based MFA.
- **Access Control**: Fine-grained permissions for file ownership and sharing.
- **Audit Logging**: Tracks critical operations for accountability.
- **Command-Line Interface**: User-friendly menu for easy interaction.
- **Lightweight Database**: Uses SQLite for efficient user and log management.

## Prerequisites
- **Python**: Requires Python 3.11 or later.
- **Operating System**: Tested on Windows 11.0 (should work on Linux/macOS with minor adjustments).
- **Dependencies**: Listed in `requirements.txt` for Python packages.
- **Network Access**: Client and Server communicate over a network (default: localhost).

## Usage

1. **Configure Administrator Account**:
   - Open `SourceCode/Server/config.py`.
   - Update the `ADMIN_USER` constant with a valid email address to receive OTPs for administrator access (e.g., to view logs).
   - Example:
     ```python
     ADMIN_USER = "your.email@example.com"
     ```

2. **Run the Server**:
   Open a terminal tab, navigate to the Server directory, and start the server:
   ```bash
   cd SourceCode/Server
   python3 server.py
   ```

3. **Run the Client**:
   Open another terminal tab, navigate to the Client directory, and start the client:
   ```bash
   cd SourceCode/Client
   python3 client.py
   ```

4. **Interact with the Client**:
   - Follow the command-line menu to:
     - **Register**: Use your email as the username and set a password. An OTP will be sent to your email for verification.
     - **Login**: Enter your email and password, followed by the OTP sent to your email.
     - **Upload/Download Files**: Upload files (encrypted locally) or download and decrypt files.
     - **Share Files**: Share files with designated users.
     - **Reset Password**: Request a password reset via email OTP.
     - **Administrator Actions**: Log in with the `ADMIN_USER` account to view system logs.

5. **Testing Notes**:
   - The database contains test accounts with personal emails requiring OTPs. For testing, register a new account with your email to receive OTPs.
   - To test administrator log access, ensure the `ADMIN_USER` email is one you control, then register and log in as prompted.

## Configuration Details

- **Server Configuration** (`SourceCode/Server/config.py`):
  - `ADMIN_USER`: Email address for the administrator account to access logs.
  - Default network settings: Server runs on `localhost:5000` (adjustable in `server.py` if needed).

- **Client Operations**:
  - **Register**: `username` (email), `password` (hashed), OTP verification.
  - **Login**: Username, password, and OTP.
  - **Upload**: Encrypts files locally using a secure key (stored client-side).
  - **Download**: Decrypts files using the stored key.
  - **Share**: Specifies usernames to share files with.
  - **Log Audit**: Administrator can view logs of login, logout, upload, delete, and share actions.

- **Database**: Uses SQLite to store user information and logs (created automatically by `server.py`).

## Example Workflow

1. Start the server and client:
   ```bash
   # Terminal 1
   cd SourceCode/Server
   python3 server.py

   # Terminal 2
   cd SourceCode/Client
   python3 client.py
   ```

2. Register a new user:
   - Select "Register" from the client menu.
   - Enter your email (e.g., `your.email@example.com`), a password, and the OTP sent to your email.

3. Upload a file:
   - Select "Upload File" and specify a file path (e.g., `test.txt`).
   - The file is encrypted and uploaded to the server.

4. Share a file:
   - Select "Share File," enter the file name and the target user’s email.

5. View logs (as administrator):
   - Log in with the `ADMIN_USER` account and select "View Logs" to see audit records.

6. Exit:
   - Select "Exit" from the client menu to close the client.

## Error Handling

- **Invalid Filenames**: Prevents attacks like path traversal (e.g., `../file.txt`).
- **SQL Injection**: Sanitizes inputs to protect the SQLite database.
- **Unauthorized Access**: Ensures only authorized users access files or logs.
- **Invalid OTP**: Prompts for a valid OTP during registration or login.
- **Server Passive Adversary**: Client-side encryption ensures the server cannot read plaintext files.
- **Unauthorized User**: MFA and access controls prevent unauthorized access to user files.

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please ensure your code includes comprehensive comments and follows the project’s security requirements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or issues, please open an issue on GitHub or contact the team coordinator at [dylan.haryoto@connect.polyu.hk](mailto:dylan.haryoto@connect.polyu.hk).

---

*Last updated: July 1, 2025*
