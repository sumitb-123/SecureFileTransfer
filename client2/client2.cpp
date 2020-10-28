#include <bits/stdc++.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include<unistd.h>
#include <string.h>
#include <iostream>
#include<pthread.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <sstream>
#include "/home/sumit/second_sem/SNS/assignment1/cryptopp-master/osrng.h"
#include "/home/sumit/second_sem/SNS/assignment1/cryptopp-master/integer.h"
#include "/home/sumit/second_sem/SNS/assignment1/cryptopp-master/nbtheory.h"
#include "/home/sumit/second_sem/SNS/assignment1/cryptopp-master/dh.h"
#include "/home/sumit/second_sem/SNS/assignment1/cryptopp-master/secblock.h"
#include "/home/sumit/second_sem/SNS/assignment1/cryptopp-master/des.h"
#define BUFF_SIZE 1024
#define trd 10
#define MIN_BUFF 1024

using namespace std;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Integer;
using CryptoPP::ModularExponentiation;
using CryptoPP::DH;
using CryptoPP::SecByteBlock;
using CryptoPP::byte;

int port_server = 9001;
string ip = "127.0.0.1";

string ACK = "YES";
string NACK = "NO";

struct header{
	int opcode;
	char data[64];
	char file_data[MIN_BUFF];
	int datasize;
};

struct publicKey{
    char prime[64];
    char gen[64];
    char Y[64];
};

Integer deskey1, deskey2,deskey3;

void convertToSec(Integer& x,CryptoPP::SecByteBlock & bytes){
    size_t encodedSize = x.MinEncodedSize(Integer::UNSIGNED);
    bytes.resize(encodedSize);
    x.Encode(bytes.BytePtr(), encodedSize, Integer::UNSIGNED);
}

//code for DES
void DES_Process(const char *keyString, byte *block, size_t length, CryptoPP::CipherDir direction){
    using namespace CryptoPP;

    byte key[DES_EDE2::KEYLENGTH];
    memcpy(key, keyString, DES_EDE2::KEYLENGTH);
    BlockTransformation *t = NULL;

    if(direction == ENCRYPTION)
        t = new DES_EDE2_Encryption(key, DES_EDE2::KEYLENGTH);
    else
        t = new DES_EDE2_Decryption(key, DES_EDE2::KEYLENGTH);

    int steps = length / t->BlockSize();
	if(length % t->BlockSize())
		++steps;
    for(int i=0; i<steps; i++){
        int offset = i * t->BlockSize();
        t->ProcessBlock(block + offset);
    }

    delete t;
}

string toString(Integer n){
	ostringstream st;
	st << n;
	string s = st.str();
	return s;
}

bool keyExchange(int client_socket){
	cout<<"Key Exchange "<<endl;
	char buffer[BUFF_SIZE];
	//Integer deskey1, deskey2,deskey3;
	// Extract the prime and base. These values could also have been hard coded 
	// in the application
	for(int i=0;i<3;i++){
		//creating structure
		struct publicKey keys;
		AutoSeededRandomPool rngA;
	    DH dhA;
    	dhA.AccessGroupParameters().Initialize(rngA, 64);

		Integer iPrime = dhA.GetGroupParameters().GetModulus();
		int len = sizeof(iPrime);
		string prime = toString(iPrime);
		cout<<"prime = "<<iPrime<<endl;

		Integer iGenerator = dhA.GetGroupParameters().GetSubgroupGenerator();
		len = sizeof(iGenerator);
        string gen = toString(iGenerator);
        cout<<"generator = "<<iGenerator<<endl;

		SecByteBlock privA(dhA.PrivateKeyLength());
        SecByteBlock pubA(dhA.PublicKeyLength());
		SecByteBlock sharedA(dhA.AgreedValueLength());
        // Generate a pair of integers for Alice. The public integer is forwarded to Bob.
        dhA.GenerateKeyPair(rngA, privA, pubA);

        Integer pbA;
		pbA.Decode(pubA.BytePtr(), pubA.SizeInBytes());
		string pubKey = toString(pbA);
		len = sizeof(pbA);
		
		memcpy(keys.prime,prime.c_str(),sizeof(prime));
		memcpy(keys.gen,gen.c_str(),sizeof(gen));
		memcpy(keys.Y,pubKey.c_str(),sizeof(pubKey));
		cout<<"PUBKEY"<<endl;
		send(client_socket,&keys, sizeof(keys),0);
        cout<<"PUBKEY Received"<<endl;
		recv(client_socket,&keys,sizeof(keys), 0);
		
		memcpy(buffer,keys.Y,sizeof(keys.Y));
		
		Integer pubB =  Integer(buffer);

		SecByteBlock pbB;
		convertToSec(pubB,pbB);
        
		if(!dhA.Agree(sharedA, privA, pbB)){
			throw std::runtime_error("Failed to reach shared secret");
			return false;
		}

		Integer sharedKey;
		sharedKey.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());

		if(i == 0) 
			deskey1 = sharedKey;
		else if(i==1)
			deskey2 = sharedKey;
		else deskey3 = sharedKey;

		cout<<"shared key "<<sharedKey<<endl;

	}
	cout<<"Key Exchange Successful"<<endl;
	//cout<<deskey1<<"  "<<deskey2<<" "<<deskey3<<endl;
}

void tripleDES(char *data){
	//cout<<"data size "<<sizeof(data)<<endl;
	SecByteBlock ky1,ky2,ky3;
    convertToSec(deskey1,ky1);
    convertToSec(deskey2,ky2);
    convertToSec(deskey3,ky3);
    char key1[sizeof(ky1)];
    char key2[sizeof(ky2)];
    char key3[sizeof(ky3)];
    memcpy(key1,ky1,sizeof(ky1));
    memcpy(key2,ky2,sizeof(ky2));
    memcpy(key3,ky3,sizeof(ky3));
    DES_Process(key3, (byte*)data, 1024, CryptoPP::DECRYPTION);
    DES_Process(key2, (byte*)data, 1024, CryptoPP::ENCRYPTION);
    DES_Process(key1, (byte*)data, 1024, CryptoPP::DECRYPTION);
	//memcpy(data,data,len);
}

bool fileTransefer(string file_name, int client_socket){
	struct header request;
	char buffer[BUFF_SIZE];
	char tbuffer[MIN_BUFF];
	int  n, count = 0;
	int len=0;
	bool sync = true;
	request.opcode = 20;
	strcpy(request.data, file_name.c_str());
	cout<<"REQSERV"<<endl;
	send(client_socket,&request,sizeof(request),0);
	recv(client_socket,buffer,BUFF_SIZE,0);
	if(buffer == ACK){
		FILE *fp = fopen(file_name.c_str(), "wb");
		recv(client_socket,&n,sizeof(int),0);
		cout<<"size = "<<n<<endl;
		while(n > 0){
			send(client_socket,&sync,sizeof(sync),0);
			memset(buffer,'\0', MIN_BUFF);
			//recv(client_socket,&request,sizeof(request),0);
			recv(client_socket,&len,sizeof(int),0);
			recv(client_socket,buffer,MIN_BUFF,0);
			//if(request.datasize <= 0 || request.datasize > 1024) request.datasize = 1024;
         	//n = n - request.datasize;
         	n = n - len;
         	//memcpy(buffer,request.file_data,MIN_BUFF);
         	tripleDES(buffer);
			//if(request.datasize != 1024)
         	//	cout<<" n = "<<n<<" rs  "<<request.datasize<<endl;
         	//fwrite(buffer, sizeof(char), request.datasize, fp);
         	fwrite(buffer, sizeof(char), len, fp);
			fflush(fp);
			//cout<<count<<endl;
    	}
	}
	else{
		cout<<"File not present"<<endl;
	}
	return true;
}

//int socket(int domain, int type, int protocol);
int main(int argc, char* argv[]){
	
	Integer desk1, desk2,desk3;
    char buffer[BUFF_SIZE];
	//connecting to the tracker
    int client_socket;
    
	//creating socket for the communication
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    
	//structure for defining the connection attributes
    struct sockaddr_in server;
    
	//assigning values to the structure like type, port and address 
    server.sin_family = AF_INET;
    server.sin_port = htons(port_server);
    server.sin_addr.s_addr = inet_addr(ip.c_str());
    int addrlen = sizeof(sockaddr);
    
	//binding the address
    bind(client_socket, (struct sockaddr*) &server, sizeof(server));
	int status = connect(client_socket, (struct sockaddr*) &server, sizeof(server));
    
	if(status<0){
        cout<<"Error in connection establishment "<<endl;
    }

	struct header data;
	string ocode;
	string file_name;
	cout<<"Request for Key Exchange(PUBKEY)"<<endl;
	data.opcode = 10;
	send(client_socket,&data,sizeof(data),0);
	recv(client_socket,buffer,BUFF_SIZE,0);
	cout<<buffer<<endl;
	if(buffer == ACK){
		if(keyExchange(client_socket)){
			//file exchange
			while(1){
				cout<<"Requesting for the File"<<endl;
    	        cout<<"Enter file name"<<endl;
	            cin>>file_name;
				if(fileTransefer(file_name,client_socket)){
				cout<<"Want to disconnect(YES)"<<endl;
				cin>>ocode;
				if(ocode == "YES"){
                	cout<<"Disconnecting ... "<<endl;
                	data.opcode = 50;
                	send(client_socket,&data,sizeof(data),0);
                	recv(client_socket,buffer,BUFF_SIZE,0);
                	if(buffer == ACK){
                    	cout<<"Disconnected"<<endl;
                	}
                	else{
                    	cout<<"Improperly Disconnected"<<endl;
                	}
					break;
				}
               }
			else{
					cout<<"File Transefer Failed"<<endl;
				}

			}
			/*if(fileTransefer(file_name,client_socket)){
				cout<<"Disconnecting ... "<<endl;
				data.opcode = 50;
				send(client_socket,&data,sizeof(data),0);
				recv(client_socket,buffer,BUFF_SIZE,0);
				if(buffer == ACK){
					cout<<"Disconnected"<<endl;
				}
				else{
					cout<<"Improperly Disconnected"<<endl;
				}
			}*/
		}
		else{
			cout<<"DF key exchange failed"<<endl;
		}


	}

    //closing the socket
    close(client_socket);

    return 0;
}
