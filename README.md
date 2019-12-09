## Secure File Transfer Application

Design and implemention of a secure Internet file transfer application/protocol. The program will include several security requirements as outlined below. 

### Supported Functionality 
*	Client should be able to upload files to the server in a secure fashion. Client also downloads files from server in a secure fashion. 
*	When the file is uploaded or downloaded, it should be intact, i.e. it should retain its features. For instance, if it is executable, it should be able to run, or if it is an image, the image must be same as the original file. 
*	Client only needs to authenticate the server. The server need not authenticate client. 
*	The only technology that is allowed for securing communication is keyed hash, e.g. SHA-256. 

### Security Requirements 

The application will include the following security requirements: 
1.	**Authentication**: Client authenticates the server using server’s RSA public key. 
2.	**Confidentiality**: The messages exchanged between client and server will be protected from exposure to others that are not authorized to read what is being communicated. The only security primitive that is available to build a confidential communication mechanism is a keyed hash, e.g. SHA-256. Part of the project is designing a communication protocol that is secure against well-known attacks on confidentiality. 
3.	**Integrity**: The possible message alteration in transit should not go undetected by the communicating parties. Again, you can only use a keyed hash mechanism to achieve this.

***

### Technical Specs

    * Python3
    * SHA256
    * RSA Key Generation and usage
  
### Prerequisites
* Python3
* MultiThreading and Socket Programming
* Cryptographic Hash Functions
* Public Key Cryptography
* Python pip package: PyCryptodome
*** 

### Execution

1) Make sure to install PyCryptodome library
```python
    $ pip install pycryptodome
```
2) Clone the repo 
```
    $ git clone https://github.com/ChandraKiranSaladi/Secure-File-Transfer-Application.git
```
3) Place the files you wish to transfer to server inside client_directory and files to transfer to client inside server_directory
4) Open 2 terminals to and execute server and client python files respectively
```python
    $ python server.py
    $ python client.py
```
5) Choose options from the client terminal to list server files, client files or upload, download documents
6) Choose exit when you wish to exit the application

### Team Members

* Chandra Kiran Saladi
* Sourik Dhua