# Secure-Storage Group 10
1. Please install python>=3.11 from https://www.python.org/downloads/release/python-3110/ 
2. Open Terminal/Powershell, execute the following to import the packages needed into a virtual environment: 
2.1. cd to Group10/sourcecode/
2.2. python -m venv .venv
2.3. .venv\Scripts\Activate.ps1 (PowerShell) 
2.4. pip (or pip3) install -r requirements.txt
3. Split Terminal/Powershell as two tabs
4. One further cd to Group10/sourcecode/Client, the other cd to Group10/sourcecode/Server
5. Run "python3 client.py" in the tab at the Client folder.
6. Run "python3 server.py" in the other tab at the Server folder.
7. Because we use OTP to implement two-factor authentication, the users left in the database (our personal emails for testing) cannot be logged in without getting the OTP from our emails. So we kindly request you to register with your email address as the username and log in with this email to test our project.
8. To test the administrator's access to system log, To specify the administrator (by default it is an email controlled by us, you may change it as a valid email where you can receive emails), please go to Group10/sourcecode/Server/config.py and change the "ADMIN_USER" constant accordingly. After specifying this "ADMIN_USER" constant, please go through the normal procedure as prompted by our system to register and log in to this administrator account when you want to check the system logs.   
9. Thank you very much for your patience, time, and efforts in testing our project! We would be glad to respond to any questions related to this project with our coordinator's email: dylan.haryoto@connect.polyu.hk
