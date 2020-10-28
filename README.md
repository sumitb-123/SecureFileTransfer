## SecureFileTransfer

This program is implementation of Secure File Transfer using symmetric key. Multiple client can request for a file simultaneously.

Step 1. Public and private key genaration:
   
   Using Diffie Hellman Algorithm generating three pairs of public and private keys.
   
   Through structure sharing the prime no. p generator g and public key(Y) with the server. Then we are settling on symetric keys.

step 2. Request for a File
   
   After settling on three symmetric keys requesting for a file.

   Server checks for the file and acknowledge(YES or NO).

step 3. Request for File transfer

   If the acknowledgement is positive asking for the file transfer.

step 4. Data Encryption and Transfer

  Server reads the file in the chunks of 1024 Bytes Encrypts the data with  3DES algorithm.
	(DATA --Enc(key1)--> DATA1 ---Dcr(key2)--->DATA2---Enc(key3)--->DATA3)
   
  After Encryption data is put into the structure and send to the requested client.
   
step 4. Data decryption and file write

  client receives the Encrypted data and decrypts it using 3DES Algorithm.
	(DATA3--Dcr(key3)--> DATA2 ---Enc(key2)--->DATA1---Dcr(key1)--->DATA)
  After Decryption data is written into the file and requests for the next chunk.

step 5. Disconnection

  After file transfer client sends disconnection packet and server responds with acknowledgement.

  connection closed.
