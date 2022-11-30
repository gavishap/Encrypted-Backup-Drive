#include "Client.h"

std::string ClientIdAsString(ClientID clientId)
{
	std::stringstream ss;
	for (int i = 0; i < 16; ++i)
	{
		ss << std::hex << (((int)clientId[i] & 0xF0) >> 4);
		ss << std::hex << (((int)clientId[i] & 0x0F) >> 0);
	}
	return  ss.str();
}

std::string ClientPubKeyAsString(ClientPublicKey clientPubKey)
{
	std::stringstream ss;
	for (int i = 0; i < 160; ++i)
	{
		ss << std::hex << (((int)clientPubKey[i] & 0xF0) >> 4);
		ss << std::hex << (((int)clientPubKey[i] & 0x0F) >> 0);
	}
	return  ss.str();
}