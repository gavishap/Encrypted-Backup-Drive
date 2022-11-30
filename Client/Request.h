#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <array>
#include <iostream>
#include <iomanip>

#include "Response.h" /* include Message inside */
class Request
{
	ClientID m_client_ID;
	char m_Version;
	short m_Code;


protected:
	static constexpr int HeaderPayloadSize = 23;
	int m_Payload_size;
	char* m_full_payload = nullptr;
	Request(short code) : m_client_ID({}), m_Version(0), m_Code(code), m_Payload_size(HeaderPayloadSize) {   }
	Request(short code, std::array<char, 16> client_ID) : m_client_ID(client_ID), m_Version(0), m_Code(code), m_Payload_size(HeaderPayloadSize) {  }
	//Request(std::array<char, 16> client_ID, char version, short code, int payload_size) : m_client_ID(client_ID), m_Version(version), m_Code(code), m_Payload_size(payload_size) {  }
	virtual ~Request() {delete m_full_payload; }



	void toBytes(int value,int offset, int sizeOfBytes)
	{
		for (int i = 0; i < sizeOfBytes; ++i)
		{
			m_full_payload[offset + i] = value >> i*8;
		}
	}

	virtual void serialize()
	{
		if (m_full_payload != nullptr)
		{
			std::copy(m_client_ID.begin(), m_client_ID.end(), m_full_payload);
			m_full_payload[16] = m_Version;
			toBytes(m_Code, 17, 2);
			toBytes(m_Payload_size, 19, 4);
		}
	}; /*  = 0; encode request and insert to payload, update payload_size */
public:

	char* getPayload() 
	{ 
		return m_full_payload;
	}

	int getPayloadSize()
	{
		return m_Payload_size;
	}
};


class RegisterRequest : public Request
{
	static constexpr short Code = 1100;
	static constexpr int NameMaxSize = 255;
	std::array<char, 16> client_ID = {NULL, NULL, NULL , NULL , NULL , NULL ,NULL ,NULL ,NULL ,NULL ,NULL ,NULL ,NULL ,NULL ,NULL ,NULL };

	char m_Name[NameMaxSize];
	//ClientPublicKey m_Public_Key;

public:
	RegisterRequest(const std::string& name) : Request(Code, client_ID){
		std::strncpy(m_Name, name.c_str(), NameMaxSize);
		serialize();
	}

	void serialize()
	{
		m_Payload_size += NameMaxSize ;	// add son fields size to the payload_size
		m_full_payload = new char[m_Payload_size];				// allocate payload memory
		Request::serialize();								// serialize father basize fields
		char* payloadPointerAfterHeader = m_full_payload + HeaderPayloadSize;	// set pointer to the section after the header
		// copy son fields to payload
		std::copy(m_Name, m_Name + NameMaxSize, payloadPointerAfterHeader);
	}
};

class SendPubKeyRequest : public Request
{
	static constexpr short Code = 1101;
	static constexpr int NameMaxSize = 255;
	static constexpr int PublicKeyMaxSize = 160;

	char m_Name[NameMaxSize];
	ClientPublicKey m_Public_Key;

public:
	SendPubKeyRequest(const std::string& name, const std::string& public_key) : Request(Code) {
		std::strncpy(m_Name, name.c_str(), NameMaxSize);
		std::copy(public_key.begin(), public_key.begin() + PublicKeyMaxSize, m_Public_Key.begin());
		serialize();
	}

	void serialize()
	{
		m_Payload_size += NameMaxSize + PublicKeyMaxSize;	// add son fields size to the payload_size
		m_full_payload = new char[m_Payload_size];				// allocate payload memory
		Request::serialize();								// serialize father basize fields
		char* payloadPointerAfterHeader = m_full_payload + HeaderPayloadSize;	// set pointer to the section after the header
		// copy son fields to payload
		std::copy(m_Name, m_Name + NameMaxSize, payloadPointerAfterHeader);
		std::copy(m_Public_Key.begin(), m_Public_Key.begin() + PublicKeyMaxSize, payloadPointerAfterHeader + NameMaxSize);
	}
};



class SendEncryptedFile : public Request
{
	static constexpr int Code = 1103;
	ClientID m_ClientID;
	static constexpr int FileNameMaxSize = 255;
	char m_fileName[FileNameMaxSize];
	std::string m_FileContent;
	int m_ContentSize;

public:
	
	SendEncryptedFile(ClientID client_ID, std::string filecontent, int contentsize, const std::string& Filename) :
		m_ClientID(client_ID), m_FileContent(filecontent), m_ContentSize(contentsize), Request(Code, client_ID)
	{
		std::strncpy(m_fileName, Filename.c_str(), FileNameMaxSize);
		serialize();
	}


	void serialize()
	{
		m_Payload_size += 275 + m_ContentSize;	// add son fields size to the payload_size
		m_full_payload = new char[m_Payload_size];				// allocate payload memory
		Request::serialize();								// serialize father basize fields
		char* payloadPointerAfterHeader = m_full_payload + HeaderPayloadSize;	// set pointer to the section after the header
		// copy son fields to payload
		std::copy(m_ClientID.begin(), m_ClientID.end(), payloadPointerAfterHeader);
		toBytes(m_ContentSize, 16 + HeaderPayloadSize, 4);
		std::copy(m_fileName, m_fileName + FileNameMaxSize, payloadPointerAfterHeader + 20);
		std::copy(m_FileContent.begin(), m_FileContent.end(), payloadPointerAfterHeader + 275);
	}

};

class ValidChecksum : public Request
{
	static constexpr int Code = 1104;
	ClientID m_ClientID;
	static constexpr int FileNameMaxSize = 255;
	char m_fileName[FileNameMaxSize];

public:
	ValidChecksum(ClientID client_ID, const std::string& Filename) :
		m_ClientID(client_ID), Request(Code, client_ID)
	{
		std::strncpy(m_fileName, Filename.c_str(), FileNameMaxSize);
		serialize();
	}

	void serialize()
	{
		m_Payload_size += 271;	// add son fields size to the payload_size
		m_full_payload = new char[m_Payload_size];				// allocate payload memory
		Request::serialize();								// serialize father basize fields
		char* payloadPointerAfterHeader = m_full_payload + HeaderPayloadSize;	// set pointer to the section after the header
		// copy son fields to payload
		std::copy(m_ClientID.begin(), m_ClientID.end(), payloadPointerAfterHeader);
		std::copy(m_fileName, m_fileName + FileNameMaxSize, payloadPointerAfterHeader + 16);							// serialize father basic fields
	}

};

class InvalidChecksum : public Request
{
	static constexpr int Code = 1105;
	ClientID m_ClientID;
	static constexpr int FileNameMaxSize = 255;
	char m_fileName[FileNameMaxSize];

public:
	InvalidChecksum(ClientID client_ID, const std::string& Filename) :
		m_ClientID(client_ID), Request(Code, client_ID)
	{
		std::strncpy(m_fileName, Filename.c_str(), FileNameMaxSize);
		serialize();
	}

	void serialize()
	{
		m_Payload_size += 271;	// add son fields size to the payload_size
		m_full_payload = new char[m_Payload_size];				// allocate payload memory
		Request::serialize();								// serialize father basize fields
		char* payloadPointerAfterHeader = m_full_payload + HeaderPayloadSize;	// set pointer to the section after the header
		// copy son fields to payload
		std::copy(m_ClientID.begin(), m_ClientID.end(), payloadPointerAfterHeader);
		std::copy(m_fileName, m_fileName + FileNameMaxSize, payloadPointerAfterHeader + 16);							// serialize father basic fields
	}
};


class FourthInvalidChecksum : public Request
{
	static constexpr int Code = 1106;
	ClientID m_ClientID;
	static constexpr int FileNameMaxSize = 255;
	char m_fileName[FileNameMaxSize];

public:
	FourthInvalidChecksum(ClientID client_ID, const std::string& Filename) :
		m_ClientID(client_ID), Request(Code, client_ID)
	{
		std::strncpy(m_fileName, Filename.c_str(), FileNameMaxSize);
		serialize();
	}

	void serialize()
	{
		m_Payload_size += 271;	// add son fields size to the payload_size
		m_full_payload = new char[m_Payload_size];				// allocate payload memory
		Request::serialize();								// serialize father basize fields
		char* payloadPointerAfterHeader = m_full_payload + HeaderPayloadSize;	// set pointer to the section after the header
		// copy son fields to payload
		std::copy(m_ClientID.begin(), m_ClientID.end(), payloadPointerAfterHeader);
		std::copy(m_fileName, m_fileName + FileNameMaxSize, payloadPointerAfterHeader + 16);							// serialize father basic fields
	}
};
