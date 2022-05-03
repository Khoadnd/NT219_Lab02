#pragma once

#include <string>

namespace core {
using std::string;
using byte = unsigned char;

void Encrypt();
void Decrypt();

// Self explanatory
void WriteStringToFile(const string &str);

// Switches
void SwitchGetString(string &str);
void SwitchGetStringCipher(string &str);
void SwitchGetKeyAndIV(byte *&key, int &keySize, byte *&iv, bool &ivSet);
void SwitchEncrypt(string &cipher, string &plain, byte *key, int keySize,
                   byte *iv, bool ivSet);
void SwitchDecrypt(string &plain, string &cipher, byte *key, int keySize,
                   byte *iv, bool ivSet);

// Key and IV stuff
void GenKey(byte *&key, const int &keySize, byte *&iv, bool &genIV);
void GetKeyAndIVFromFile(byte *&key, int &keySize, byte *&iv, bool &ivSet);
void GetStringFromFile(string &str);
void GetString(string &str);
void GetCipherString(string &str);
void ReadKeyAndIVFromKeyBoard(byte *&key, int &keySize, byte *&iv, bool &ivSet);

// Pretty print
string PrettyPrint(byte arr[], int arraySize);
string PrettyPrint(string text);
} // namespace core