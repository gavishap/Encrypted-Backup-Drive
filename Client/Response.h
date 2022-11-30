#pragma once
#include <algorithm>
#include <array>
#include <memory>
#include <vector>
#include "Message.h" /* include Client inside*/


class Response
{
	char m_Version;
	short m_Code;
	int m_Payload_size;
	const unsigned char* m_payload = nullptr;

protected:
	Response(char Version, short Code, const unsigned char* payload, int payloadSize) : m_Version(Version), m_Code(Code), m_payload(payload), m_Payload_size(payloadSize){}
	~Response() {}

public:
	static unsigned int fromBytes(const unsigned char* payload, int offset, int sizeOfBytes);
	static std::shared_ptr<Response> CreateResponse(const unsigned char* header, const unsigned char* payload);
	short GetCode() { 
		if (this == nullptr)
			return 0;
		return m_Code; 
	}
};

class ErrorResponse : public Response
{
public:
	ErrorResponse(char Version, short Code) : Response(Version, Code, nullptr, 0) {}
};

class RegisterSuccessResponse : public Response
{
	ClientID m_ClientID;
public:
	RegisterSuccessResponse(char Version, short Code, const unsigned char* payload, int payloadSize) : Response(Version, Code, payload, payloadSize)
	{
		std::copy(payload, payload + 16, m_ClientID.begin());
	}


	std::string ClientIdAsString()
	{
		std::stringstream ss;
		for (int i = 0; i < 16; ++i)
		{
			ss << std::hex << (((unsigned char)m_ClientID[i] & 0xF0) >> 4);
			ss << std::hex << (((unsigned char)m_ClientID[i] & 0x0F) >> 0);
		}
		return  ss.str();
	}
};

class Recieve_encrypted_AES : public Response
{
	ClientID m_ClientID;
	Encrypted_Aes m_encrypted_AES;
public:
	Recieve_encrypted_AES(char Version, short Code, const unsigned char* payload, int payloadSize) : Response(Version, Code, payload, payloadSize)
	{
		std::copy(payload, payload + 16, m_ClientID.begin());
		std::copy(payload + 16, payload + 16 + 128, m_encrypted_AES.begin());
	}

	Encrypted_Aes GetEncryptedAES() { return m_encrypted_AES; }
};
 
class CRCCheckFileResponse : public Response
{
	std::array<char, 16> m_ClientID;
	ContentSize m_ContentSize;
	ClientName fileName;
	ContentSize checksum;

public:
	CRCCheckFileResponse(char Version, short Code, const unsigned char* payload, int payloadSize) : Response(Version, Code, payload, payloadSize)
	{
		std::copy(payload, payload + 16, m_ClientID.begin());
		std::copy(payload + 16, payload + 16 + 4, m_ContentSize.begin());
		std::copy(payload + 16 + 4, payload + 16 + 4 + 255, fileName.begin());
		std::copy(payload + 16 + 4 + 255, payload + 16 + 4 + 255+4, checksum.begin());
	}

	unsigned int GetChecksum()
	{
		int int_checksum = int((unsigned char)(checksum[3]) << 24 |
			(unsigned char)(checksum[2]) << 16 |
			(unsigned char)(checksum[1]) << 8 |
			(unsigned char)(checksum[0]));
		return int_checksum;
	}
};

class FileRecievedSuccessfully : public Response
{
	ClientName fileName;

public:
	FileRecievedSuccessfully(char Version, short Code, const unsigned char* payload, int payloadSize) : Response(Version, Code, payload, payloadSize)
	{
		std::copy(payload , payload +255, fileName.begin());
	}
};


