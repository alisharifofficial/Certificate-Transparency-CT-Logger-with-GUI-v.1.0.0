Certificate Transparency CT Logger The program's core functionality is divided into two parts:

Certificate Generation: The first part uses the cryptography library to programmatically generate a private key and a self-signed certificate. Instead of relying on a third-party Certificate Authority (CA), the program signs the certificate itself, making it a "self-signed" certificate. The script then saves the key and certificate to two files, key.pem and cert.pem, for later use.

Secure Web Server: The second part of the program uses the Flask web framework to create a simple server. It loads the previously generated key.pem and cert.pem files into an SSL context. This context is passed to the Flask application's run() method, which enables HTTPS and ensures all traffic between the server and a browser is encrypted. When a browser connects to the server, it receives the self-signed certificate and typically displays a security warning because it can't verify the certificate with a trusted public CA. This is an expected and educational outcome of the program.

The program is a powerful learning tool for understanding how SSL/TLS works under the hood, showing the direct relationship between a private key, a certificate, and secure web communication. License This project is licensed under the MIT License - see the LICENSE file for details.

Third-Party Libraries This project uses the following open-source libraries:

pandas (BSD 3-Clause License) Faker (MIT License) OpenPyXL (MIT License)



Certificate-Transparency-CT-Logger-v.1.0.0