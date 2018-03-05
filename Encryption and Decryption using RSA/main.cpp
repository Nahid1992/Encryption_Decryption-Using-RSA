#include <stdio.h>
#include <iostream>
#include <string>
#include <ctime>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int KEYSIZE = 6000;

using namespace std;

unsigned char * randGen(){
	char *col = new char[256]; 
	
		
	int i = 0;
	for (i=0;i<256;i++){
		//int value = rand() % 32+1;
		int value = 65 + (rand() % static_cast<int>(90 - 65 + 1));
		col[i] = value;
    	//cout<<col[i];
    	
    }    
  	
  	col[i] = '\0';
  	
  	unsigned char* ucol=(unsigned char*)col;

    return ucol;
}


RSA * createRSA(unsigned char * key, int isPublic){

	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key,-1);
	
	if(keybio==NULL){
		cout<<"Failed to create key BIO"<<endl;
		return 0;
	}
	
	if(isPublic == 1){
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
	}
	else if(isPublic == 0) {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
	}
	
	return rsa;
}


RSA * createRSAWithFilename(char * filename,int isPublic)
{
    FILE * fp = fopen(filename,"rb");
 
    if(fp == NULL)
    {
        printf("Unable to open file %s \n",filename);
        return NULL;    
    }
    
    RSA *rsa= RSA_new();
 
    if(isPublic == 1)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }
 
    return rsa;
}


//Public Encryption and Private Decryption
int public_encrypt(unsigned char * data,int data_len,unsigned char *encrypted)
{
	int padding = RSA_PKCS1_PADDING;

	//RSA * rsa = createRSA(key,1);
	char * filename = new char[1024];
	strcpy(filename,"keys/6000/public.pem");	
	RSA * rsa = createRSAWithFilename(filename,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding); //changed
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char *decrypted)
{	
	int padding = RSA_PKCS1_PADDING;
    //RSA * rsa = createRSA(key,0);
    char * filename = new char[1024];
	strcpy(filename,"keys/6000/private.pem");
	RSA * rsa = createRSAWithFilename(filename,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding); //changed
    return result;
}


//Private Key Encryption and Public Key Decryption
int private_encrypt(unsigned char * data,int data_len,unsigned char *encrypted)
{
	int padding = RSA_PKCS1_PADDING;
    //RSA * rsa = createRSA(key,0);
    char * filename = new char[1024];
	strcpy(filename,"keys/6000/private.pem");	
	RSA * rsa = createRSAWithFilename(filename,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int public_decrypt(unsigned char * enc_data,int data_len,unsigned char *decrypted)
{
	int padding = RSA_PKCS1_PADDING;
    //RSA * rsa = createRSA(key,1);
    char * filename = new char[1024];
	strcpy(filename,"keys/6000/public.pem");	
	RSA * rsa = createRSAWithFilename(filename,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}





//Main Functions:
void En_Pub_De_Priv(unsigned char * plainText,int sizeLength,int enSize,int deSize){

//.:Public Encryption and Private Decryption:.
	cout<<".:Public Encryption and Private Decryption:."<<endl;
	
	unsigned char  encrypted[enSize]={};
	unsigned char decrypted[deSize]={};
	
	//Encryption

	int encrypted_length= public_encrypt(plainText,sizeLength,encrypted);	
	if(encrypted_length == -1)
	{		
		cout<<"Public Encrypt failed!"<<endl;
		exit(0);
	}
	cout<<"Encryption Done..."<<endl;	
		 
	//Decryption	 
	int decrypted_length = private_decrypt(encrypted,encrypted_length,decrypted);
	if(decrypted_length == -1)
	{
		cout<<"Private Decrypt Failed"<<endl;
		exit(0);
	}
	cout<<"Decryption Done..."<<endl;
	
	//Rsults:
	//cout<<"-Results-"<<endl;
	//cout<<"Encrypted Text = "<<plainText<<endl;
	//cout<<"Decrypted Text = "<<decrypted<<endl;
	
	  
	
}
void En_Priv_De_Pub(unsigned char * plainText,int sizeLength,int enSize, int deSize){

	//.:Private Key Encryption and Public Key Decryption:.
	cout<<".:Private Encryption and Public Decryption:."<<endl;
	
	unsigned char  encrypted[enSize]={};
	unsigned char decrypted[deSize]={};
	
	int encrypted_length= private_encrypt(plainText,sizeLength,encrypted);
	if(encrypted_length == -1)
	{
		cout<<"Private Encrypt failed"<<endl;;
		exit(0);
	}	
	cout<<"Encryption Done..."<<endl;
	
	 
	int decrypted_length = public_decrypt(encrypted,encrypted_length,decrypted);
	if(decrypted_length == -1)
	{
		cout<<"Public Decrypt failed"<<endl;;
		exit(0);
	}
	cout<<"Decryption Done..."<<endl;

	
	//Results
	//cout<<"-Results-"<<endl;
	//cout<<"Encrypted Text = "<<plainText<<endl;
	//cout<<"Decrypted Text = "<<decrypted<<endl;
	//cout<<endl;
}




int main(){

    cout<<"Unix & Network Security: Assignment 04"<<endl;
    cout<<endl;
    double TIME = 0.0;
    double TIME2 = 0.0;
    for (int index101 = 0; index101<100;index101++)
    {
    	cout<<"RUN: "<<index101+1<<endl; 
    	
		unsigned char *text = randGen();	
		unsigned char plainText[256] = "hellow";
		int index=0;
		for(index=0;index<256;index++)	{
	
			plainText[index]=text[index];
		}
	
		plainText[index]='\0';

	
		int sizeLength = strlen((char*)plainText); 
		//cout<<"STRLEN : "<<sizeLength<<endl;
		cout<<"Original Text"<<endl;
		cout<<plainText<<endl;	
	
		int enSize = KEYSIZE;
		int deSize = KEYSIZE;	
	
		cout<<endl;
	
		clock_t begin = clock();
		En_Pub_De_Priv(plainText,sizeLength,enSize,deSize);
		clock_t end = clock();
		double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
		cout<<"Elapsed Time: "<<elapsed_secs<<"s"<<endl;
		TIME = TIME + elapsed_secs;
		
		cout<<endl;		
		
		clock_t begin2 = clock();
		En_Priv_De_Pub(plainText,sizeLength,deSize,deSize);
   		clock_t end2 = clock();
   		double elapsed_secs2 = double(end2 - begin2) / CLOCKS_PER_SEC;
   		cout<<"Elapsed Time: "<<elapsed_secs2<<"s"<<endl;
   		TIME2 = TIME2 + elapsed_secs2;
   	}
   	cout<<endl;
	cout<<"Average Time For KeySize: "<<KEYSIZE<<" := "<<TIME/100<<"s ==> Encrypted with Public Key & Decrypted with Private Key"<<endl;
	cout<<"Average Time For KeySize: "<<KEYSIZE<<" := "<<TIME/100<<"s ==> Encrypted with Private Key & Decrypted with Public Key"<<endl;
    return 0;
}
