The project will involve creating a client-server backup drive system where the client is implemented in C++ and the server is implemented in Python.
The client will be responsible for sending files to the server for backup, and the server will store the backed up files in a secure location.
All file transfers between the client and server will be encrypted to ensure the security and privacy of the data being backed up.
n addition to encrypting file transfers, the client and server will also implement checksum verification to ensure the integrity of the backed up data. 
After each file transfer, the client will calculate the checksum of the sent file and send it to the server, which will compare it to its own calculated checksum of the received file.
