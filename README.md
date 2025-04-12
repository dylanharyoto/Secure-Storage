# Secure-Storage Group 10
1. Please install python>=3.11 from https://www.python.org/downloads/release/python-3110/ 
2. Open Terminal/Powershell
3. Split Terminal/Powershell as two tabs
4. Both cd to Group10/code/, one further cd to Client folder, the other cd to Server folder
5. In the code folder, pip install -r requirements.txt
6. Run "python3 client.py" in the tab at the Client folder.
7. Run "python3 server.py" in the other tab at the Server folder.
8. Because we use OTP to implement two-factor authentication, the users left in the database (our personal emails for testing) cannot be logged in without getting the OTP from our emails. So we kindly request you to register with your email address as the username and log in with this email to test our project.
9. To test the administrator's access to system log, To specify the administrator (by default it is an email controlled by us, you may change it as a valid email where you can receive emails), please go to /SourceCode/Server/config.py and change the "ADMIN_USER" constant accordingly. After specifying this "ADMIN_USER" constant, please go through the normal procedure as prompted by our system to register and log in to this administrator account when you want to check the system logs.   
10. Thank you very much for your patience, time, and efforts in testing our project! We would be glad to respond to any questions related to this project with our coordinator's email: dylan.haryoto@connect.polyu.hk
