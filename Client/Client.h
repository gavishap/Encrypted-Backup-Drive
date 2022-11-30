#pragma once
#include <algorithm>
#include <array>
#include <memory>
#include <vector>
#include <string>

#include <sstream>
#include "AESWrapper.h"

using ClientID = std::array<char, 16>;
using ClientName = std::array<char, 255>;
using Client = std::pair<ClientID, ClientName>;
using ClientPublicKey = std::array<char, 160>;
using Encrypted_Aes = std::array<char, 128>;
using ContentSize = std::array<char, 4>;
using Client_IDandPUBKEY = std::pair<ClientID, ClientPublicKey>;
using Client_IDandSYMKEY = std::pair<ClientID, AESWrapper>;


std::string ClientPubKeyAsString(ClientPublicKey clientPubKey);
std::string ClientIdAsString(ClientID clientId);
