#include <bits/stdc++.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include<unistd.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include<pthread.h>
#include <bits/stdc++.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include<pthread.h>
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
#define MIN_BUFF 1024
#define trd 10
#define nm 100
using namespace std;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Integer;
using CryptoPP::ModularExponentiation;
using CryptoPP::DH;
using CryptoPP::SecByteBlock;
using CryptoPP::byte;

int port = 9001;
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

string toString(Integer n){
    ostringstream st;
    st << n;
    string s = st.str();
    return s;
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

void keyExchange(int client_socket){
	//Integer deskey1, deskey2,deskey3;
    char buffer[BUFF_SIZE];
	//strcpy(buffer,ACK);
	send(client_socket,ACK.c_str(),BUFF_SIZE,0);
    // Extract the prime and base. These values could also have been hard coded 
    // in the application
    for(int i=0;i<3;i++){
		struct publicKey keys;
		AutoSeededRandomPool rngB;
        Integer iPrime;
        Integer iGenerator;
        Integer pubA;
        Integer sharedKey;
		cout<<"PUBKEY Received"<<endl;
		recv(client_socket,&keys,sizeof(keys),0);
		
		memset(buffer,'\0',BUFF_SIZE);
		memcpy(buffer,keys.prime,sizeof(keys.prime));
		iPrime = Integer(buffer);
		
		memset(buffer,'\0',BUFF_SIZE);
		memcpy(buffer,keys.gen,sizeof(keys.gen));
        iGenerator = Integer(buffer);
		
		memset(buffer,'\0',BUFF_SIZE);
		memcpy(buffer,keys.Y,sizeof(keys.Y));
        pubA = Integer(buffer);
		
		cout<<"Prime and Generator Received"<<endl;
		cout<<"Prime "<<iPrime<<endl;
		cout<<"Genrator "<<iGenerator<<endl;
        
		SecByteBlock pbA;
        convertToSec(pubA,pbA);
		DH dhB(iPrime, iGenerator);
        
		SecByteBlock privB(dhB.PrivateKeyLength());
        SecByteBlock pubB(dhB.PublicKeyLength());
        SecByteBlock sharedB(dhB.AgreedValueLength());
        // Generate a pair of integers for Alice. The public integer is forwarded to Bob.
        dhB.GenerateKeyPair(rngB, privB, pubB);

        Integer pbB;
        pbB.Decode(pubB.BytePtr(), pubB.SizeInBytes());
        string pubKey = toString(pbB);
        int len = sizeof(pbB);
		memcpy(keys.Y,pubKey.c_str(),len);
		cout<<"PUBKEY"<<endl;
        send(client_socket,&keys,sizeof(keys), 0);
        cout<<"pubB = "<<pbB<<endl;

        if(!dhB.Agree(sharedB, privB, pbA))
            throw runtime_error("Failed to reach shared secret (2)");

        sharedKey.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
		cout<<"Shared Key "<<sharedKey<<endl;
        if(i == 0)
            deskey1 = sharedKey;
        else if(i==1)
            deskey2 = sharedKey;
        else deskey3 = sharedKey;

    }
	cout<<"Key Exchange Successful"<<endl;

}

bool checkFile(string file_name){
	ifstream in(file_name);
  	if(!in) return false;
	else return true;
}

void tripleDES(char *data,Integer& dkey1,Integer& dkey2, Integer& dkey3){
	
	SecByteBlock ky1,ky2,ky3;
	//cout<<"DES"<<endl;
	/*cout<<dkey1<<endl;
    cout<<dkey2<<endl;
    cout<<dkey3<<endl;*/
	convertToSec(dkey1,ky1);
	convertToSec(dkey2,ky2);
	convertToSec(dkey3,ky3);
	char key1[sizeof(ky1)];
	char key2[sizeof(ky2)];
	char key3[sizeof(ky3)];
	memcpy(key1,ky1,sizeof(ky1));
	memcpy(key2,ky2,sizeof(ky2));
	memcpy(key3,ky3,sizeof(ky3));
    DES_Process(key1, (byte*)data, 1024, CryptoPP::ENCRYPTION);
    DES_Process(key2, (byte*)data, 1024, CryptoPP::DECRYPTION);
    DES_Process(key3, (byte*)data, 1024, CryptoPP::ENCRYPTION);
}

void fileExchange(int client_socket, string file_name,Integer& key1,Integer& key2, Integer& key3){	
	cout<<"file will br transfered shortly"<<endl;
	/*cout<<key1<<endl;
    cout<<key2<<endl;
    cout<<key3<<endl;*/
	char* Buffer = new char[MIN_BUFF];
	struct header response;
    int size, n, count=0;
	FILE *fp = fopen(file_name.c_str(),"rb");
	bool sync;
    fseek (fp,0,SEEK_END);
    size = ftell(fp);
    rewind (fp);
	send (client_socket,&size,sizeof(int), 0);
	cout<<"size = "<<size<<endl;
	memset(Buffer,'\0', MIN_BUFF);
	while ((n = fread(Buffer,sizeof(char),MIN_BUFF,fp)) > 0){
		//response.opcode = 40;
		tripleDES(Buffer,key1,key2,key3);
		//cout<<"ENCMSG"<<endl;
		//memcpy(response.file_data,Buffer,MIN_BUFF);
		//response.datasize = n;
		//if(response.datasize != 1024) cout<<response.datasize<<endl;
		recv(client_socket,&sync,sizeof(sync),0);
		send (client_socket,&n, sizeof(int), 0);
		send (client_socket,Buffer, MIN_BUFF, 0);
		//send (client_socket,&response, sizeof(response), 0);
		fflush(fp);
		size = size - n;
		//cout<<"size = "<<size<<"  n = "<<n<<endl;
		memset(Buffer,'\0', MIN_BUFF);
		//cout<<count<<endl;
    }
	cout<<"REQCOM"<<endl;
    cout<<"closing the file in sending thread"<<endl;
    fclose(fp);
}

void *clientHandler(void *sock){
	cout<<"client handler "<<endl;
    int client_socket = *((int *)sock);
	struct header data;
	bool file_present;
	//keys
	Integer key1, key2,key3;
	string file_name;
	recv(client_socket,&data,sizeof(data),0);
	if(data.opcode == 10){
		cout<<"KEY EXCHANGE"<<endl;
		keyExchange(client_socket);
		key1 = deskey1;
		key2 = deskey2;
		key3 = deskey3;	
		/*cout<<key1<<endl;	
		cout<<key2<<endl;	
		cout<<key3<<endl;*/
	}
	recv(client_socket,&data,sizeof(data),0);
	if(data.opcode == 20){
		cout<<"Received request for File"<<endl;
		file_name = data.data;
		bool filePresent = checkFile(file_name);
		if(filePresent){
			send(client_socket,ACK.c_str(),BUFF_SIZE,0);
			fileExchange(client_socket,file_name,key1,key2,key3);
		}
		else send(client_socket,NACK.c_str(),BUFF_SIZE,0);
	}
	cout<<"File Transfered"<<endl;
	recv(client_socket,&data,sizeof(data),0);
	if(data.opcode == 50){
		cout<<"Closing connection"<<endl;
	}
	send(client_socket,ACK.c_str(),BUFF_SIZE,0);
	cout<<"Connection Closed"<<endl;
	//cout<<deskey1<<"  "<<deskey2<<" "<<deskey3<<endl;*/
    pthread_exit(NULL);
}


//int socket(int domain, int type, int protocol);
int main(int argc, char* argv[]){
	
	pthread_t td;
	//connecting to the tracker
	int svr_socket;
    //creating socket for the communication
    svr_socket = socket(AF_INET, SOCK_STREAM, 0);
    //structure for defining the connection attributes
    struct sockaddr_in server;
    //assigning values to the structure like type, port and address 
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip.c_str());
	int addrlen = sizeof(sockaddr);
    //binding the address
    bind(svr_socket, (struct sockaddr*) &server, sizeof(server));
    //listening to respond
    listen(svr_socket,trd);
	int opcode;

    while(1){
        //accepting request from clients
        cout<<"server is listening"<<endl;
        int client_socket = accept(svr_socket, (struct sockaddr *)&server, (socklen_t*)&addrlen);
		pthread_create(&td, NULL, clientHandler,&client_socket);
    }

    //closing the socket
    close(svr_socket);

	return 0;
}
