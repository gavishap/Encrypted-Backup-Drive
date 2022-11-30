#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <fstream>
#include "CommunicationHandler.h"
#include <iomanip>
#include <algorithm>
#include "Client.h"
#include "AESWrapper.h"
#include <map>
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h>	
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include <bitset>
#include<cstdlib>

#include <zlib.h>

using namespace std;


uint8_t crc8(uint8_t* addr, uint8_t len)
{
	uint8_t crc = 0;
	for (uint8_t i = 0; i < len; i++) {
		uint8_t inbyte = addr[i];
		for (uint8_t j = 0; j < 8; j++) {
			uint8_t mix = (crc ^ inbyte) & 0x01;
			crc >>= 1;
			if (mix)
				crc ^= 0x8C;
			inbyte >>= 1;
		}
	}
	return crc;
}


std::string toBinary(std::string const& str) 
{
	std::string binary = "";
	for (char const& c : str) {
		binary += std::bitset<8>(c).to_string() + ' ';
	}
	return binary;
}


void hexify2(const unsigned char* buffer, unsigned int length)
{
	std::ios::fmtflags f(std::cout.flags());
	std::cout << std::hex;
	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	std::cout << std::endl;
	std::cout.flags(f);
}



void writeMeInfo(std::string name, std::string uuid, std::string privateKey)
{
	std::string path = "me.info";
	std::ofstream file(path);
	if (file.is_open())
	{
		file << name << std::endl;
		file << uuid << std::endl;
		file << privateKey << std::endl;
	}
	else
		std::cout << "cant find " << path << std::endl;
}

//function to turn a string into type ClientID
ClientID parseClientID(std::string ID)
{
	int len = ID.length();
	ClientID uuid;
	for (int i = 0, j = 0; i < len; j += 1, i += 2)
	{
		std::string byte = ID.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), nullptr, 16);
		uuid[j] = chr;
	}
	return uuid;
}
/****************************************************************************
If "me.info" file already exists ,read the file and save the info in designated variables
****************************************************************************/
bool readMeInfo(std::string& name, ClientID& uuid, std::string& privateKey)
{
	std::string path = "me.info";
	std::string firstLine, secondLine, thirdLine, line;
	std::ifstream file(path);
	if (file.is_open())
	{
		file >> firstLine;
		file >> secondLine;
		name = firstLine;
		uuid = parseClientID(secondLine);
		while (std::getline(file, line))
			privateKey += line;
		return true;
	}
	else
	{
		return false;
	}
}
/****************************************************************************
Reads the transfer info file and saves the info in designated variables
****************************************************************************/
bool readTransferInfo(std::pair<std::string, int>& portInfo,std::string& name, std::string& FileName)
{
	std::string path = "transfer.info";
	std::string firstLine, secondLine, thirdLine;
	std::ifstream file(path);
	if (file.is_open())
	{
		getline(file, firstLine);
		getline(file, secondLine) ;
		getline(file, thirdLine);
		auto foundDelimiter = firstLine.find(':');
		std::string ip = firstLine.substr(0, foundDelimiter);
		std::string port = firstLine.substr(foundDelimiter + 1);
		portInfo = { ip, std::stoi(port) };
		name = secondLine;
		FileName = thirdLine;
		return true;
	}
	else
	{
		return false;
	}
}

char* getTransferFileContent(std::string fileName)
{
	FILE* fileptr;
	char* buffer;
	long filelen;

	fileptr = fopen(fileName.c_str(), "rb");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buffer = (char*)malloc(filelen * sizeof(char)); // Enough memory for the file
	fread(buffer, filelen, 1, fileptr);
	buffer[filelen] = '\0';
	fclose(fileptr); // Close the file

	return buffer;
	
	
}
/****************************************************************************
Encrypts the file contents with AES key
****************************************************************************/
std::string encrypt_file(const char* key, const char* fileContent)
{
	AESWrapper aes((unsigned char*)key, AESWrapper::DEFAULT_KEYLENGTH);
	std::string ciphertext = aes.encrypt(fileContent, ((std::string)fileContent).length());
	return ciphertext;
}

int main()
{
	/*get the transfer info and file contents*/
	std::string clientName, FileName;
	std::pair<std::string, int> portInfo;
	readTransferInfo(portInfo, clientName, FileName);
	char* file_stuff = getTransferFileContent(FileName);

	unsigned int server_checksum = 0;
	

	CommunicationHandler communication(portInfo.first, portInfo.second);
	bool isExit = false;
	/*do
	{*/
	std::shared_ptr<Request> request;
	std::shared_ptr<Response> response;
	std::string publicKey, privateKey;
	Encrypted_Aes encrypted_AES;
	ClientID clientID = {};


	/*get checksum of input file*/
	char* data = file_stuff;
	const uint8_t* dataAsUint8 = reinterpret_cast<const uint8_t*>(data);
	uint8_t* rawData = const_cast<uint8_t*>(dataAsUint8);
	uint8_t input_file_checksum = crc8(rawData, ((std::string)file_stuff).length());


	// check me.info already exists
	bool isUserRegistered = readMeInfo(clientName, clientID, privateKey);
	if (isUserRegistered)
	{
		std::cout << "Client already exists, can't register again." << std::endl;
	}

	else
	{
		//Create an RSA decryptor. this is done here to generate a new private/public key pair
		RSAPrivateWrapper rsapriv;

		privateKey = Base64Wrapper::encode(rsapriv.getPrivateKey());
	


		request = std::make_shared<RegisterRequest>(clientName);
		uint8_t* tmp = reinterpret_cast<uint8_t*>(request->getPayload());

	

		communication.sendAndReceiveMessage(request, response);

		if (response->GetCode() == 2100)
		{
			std::cout << "Client register succeeded" << std::endl;
			const auto clientIDasStr = std::static_pointer_cast<RegisterSuccessResponse>(response)->ClientIdAsString();
			for (int i = 0; i < 16; i++)
				clientID[i] = clientIDasStr[i];

			writeMeInfo(clientName, clientIDasStr, privateKey);
		}

		/*create public key to send to server*/
		publicKey = rsapriv.getPublicKey();
		std::cout << "Public key size" << publicKey.size() << std::endl;
		request = std::make_shared<SendPubKeyRequest>(clientName, publicKey);
		communication.sendAndReceiveMessage(request, response);
		if (response->GetCode() == 2102)
		{


			std::cout << "Sent Public key and recieved AES key" << std::endl;
			encrypted_AES = std::static_pointer_cast<Recieve_encrypted_AES>(response)->GetEncryptedAES();


		
		}

		/*Decrypt aes key from server with private key of client*/
		RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(privateKey));
		std::string encrypted_str(std::begin(encrypted_AES), std::end(encrypted_AES));
		std::string decrypted_AES = rsapriv_other.decrypt(encrypted_str);
		//std::cout << decrypted;


		std::cout << "file content: " << file_stuff << std::endl;

		/*Get the file content and encrypt it with the AES key*/
		AESWrapper aes((unsigned char*)decrypted_AES.c_str(), AESWrapper::DEFAULT_KEYLENGTH);
		std::string encrypted_file = aes.encrypt(file_stuff, ((std::string)file_stuff).length());


		int count_times_sent=0;

		while (count_times_sent < 4)
		{
			request = std::make_shared<SendEncryptedFile>(clientID, encrypted_file, encrypted_file.size(), FileName);

			communication.sendAndReceiveMessage(request, response);
			if (response->GetCode() == 2103)
			{

				std::cout << "file stuff length:" << ((std::string)file_stuff).length() << std::endl;
				std::cout << "Server got file" << std::endl;
				server_checksum = std::static_pointer_cast<CRCCheckFileResponse>(response)->GetChecksum();



				std::cout << "file checksum of client:" << (unsigned int)input_file_checksum << std::endl;

				std::cout << "file checksum from server:" << server_checksum << std::endl;

			}
			if (server_checksum == input_file_checksum)
			{
				request = std::make_shared<ValidChecksum>(clientID, FileName);
				cout << "same checksum" << std::endl;
				communication.sendAndReceiveMessage(request, response);
				if (response->GetCode() == 2104)
				{
					cout << "Server Recieved File Successfully!!" << std::endl;
					return 0;
				}
			}
			else
			{

				request = std::make_shared<InvalidChecksum>(clientID, FileName);
				cout << "Wrong checksum, sending again to server" << std::endl;
				communication.sendAndReceiveMessage(request, response);

			}
			count_times_sent++;
		}

		request = std::make_shared<FourthInvalidChecksum>(clientID, FileName);
		cout << "Your file is corrupted" << std::endl;
		communication.sendAndReceiveMessage(request, response);

	}
}
