Elegant E-Library

Overview

Elegant E-Library is a highly secure and efficient electronic library platform designed with advanced cryptographic and security features. This platform integrates state-of-the-art mechanisms such as SSL, self-signed certificates, 2-Factor Authentication (2FA), password hashing, encryption, and Google reCAPTCHA for robust security. Additionally, it has an SQL Injection Detection and Prevention System using Convolutional Neural Networks (CNN) that alerts the admin in real-time whenever an SQL injection attempt is detected.

Features

1. SSL and Self-Signed Certificates:

The platform uses Elliptic Curve Cryptography (ECC) with the secp521r1 curve for generating self-signed certificates, ensuring secure communication between clients and the server.



2. 2-Factor Authentication (2FA):

Adds an extra layer of protection for user logins by requiring time-based one-time passwords (OTP).



3. Password Hashing:

Passwords are securely hashed using Argon2, ensuring strong security against brute-force attacks.



4. XSS and SQL Injection Prevention:

The system implements XSS filtering, card sanitization, and rate-limiting to prevent common web vulnerabilities.

Additionally, a CNN-based SQL Injection Detection system monitors queries in real-time to detect and prevent malicious attempts.



5. Encryption:

Sensitive data is encrypted using secure cryptographic algorithms, ensuring confidentiality and data integrity.



6. Google reCAPTCHA:

Integrated reCAPTCHA to prevent automated bots from exploiting login and registration forms.



7. Rate Limiting:

Implemented rate limiting to mitigate brute-force attacks by limiting the number of login attempts from a single IP.



8. Password Policy:

Enforced password policies requiring strong, complex passwords to ensure account security.




Technologies Used

Frontend: HTML, CSS, JavaScript

Backend: Python (Flask)

Security Libraries: OpenSSL, PyCryptodome

2FA: Google Authenticator integration

Machine Learning: TensorFlow, Keras for the CNN model

Database: MySQL, SQLite

Other: Google reCAPTCHA


Installation

Prerequisites

Python 3.x

MySQL/SQLite

OpenSSL

Flask

TensorFlow, Keras

Google reCAPTCHA keys


Setup

1. Clone the repository:

git clone https://github.com/Inn0m1n4te030/Elegant-Elibrary.git
cd Elegant-Elibrary


2. Install the required Python packages:

pip install -r requirements.txt


3. Set up the database:

Create a MySQL or SQLite database.

Update the config.py or relevant Flask settings with your database credentials.



4. Set up Google reCAPTCHA keys:

Obtain the keys from the Google reCAPTCHA site and add them to the environment variables or the Flask config file.



5. Run database migrations:

flask db upgrade


6. Run the development server:

flask run


7. Access the platform at http://localhost:5000.



Security Features

SSL and Self-Signed Certificates: The platform uses ECC with secp521r1 for secure communication.

Password Hashing: Argon2 is used to hash passwords, ensuring strong resistance to brute-force attacks.

XSS and SQL Injection Protection: The system implements multiple layers of protection, including sanitization and a CNN-based detection model.

Encryption: Sensitive data is encrypted to protect user information.

Rate Limiting: Prevents brute-force attacks by limiting login attempts.


CNN Model for SQL Injection Detection

A Convolutional Neural Network (CNN) is integrated to detect SQL injection attempts in real-time, providing enhanced protection against database attacks. The system alerts the admin whenever a potential SQL injection attack is detected, enabling timely responses.

Future Enhancements

Real-time Admin Notifications: Developing a real-time dashboard to provide alerts and analytics for SQL injection attempts.

Role-Based Access Control (RBAC): Implement different user roles for better access management.


Contributing

Contributions are welcome! Please follow the steps below to contribute:

1. Fork the repository.


2. Create a new feature branch (git checkout -b feature-name).


3. Commit your changes (git commit -m 'Add some feature').


4. Push to the branch (git push origin feature-name).


5. Create a pull request.



License

This project is licensed under the MIT License. See the LICENSE file for details.

Contact

For further inquiries or issues, please contact the project maintainer:

Moe Thu Kyaw – moethukyaw2022@gmail.com
