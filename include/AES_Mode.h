#pragma once

#include <string>

namespace AES_ED {

using byte = unsigned char;
using std::string;

string ECBMode_Encrypt(string plain, byte key[], int keySize);
string ECBMode_Decrypt(string plain, byte key[], int keySize);
string CBCMode_Encrypt(string plain, byte key[], int keySize, byte iv[]);
string CBCMode_Decrypt(string plain, byte key[], int keySize, byte iv[]);
string CFBMode_Encrypt(string plain, byte key[], int keySize, byte iv[]);
string CFBMode_Decrypt(string plain, byte key[], int keySize, byte iv[]);
string CTRMode_Encrypt(string plain, byte key[], int keySize, byte iv[]);
string CTRMode_Decrypt(string plain, byte key[], int keySize, byte iv[]);
string OFBMode_Encrypt(string plain, byte key[], int keySize, byte iv[]);
string OFBMode_Decrypt(string plain, byte key[], int keySize, byte iv[]);
string XTSMode_Encrypt(string plain, byte key[], int keySize, byte iv[]);
string XTSMode_Decrypt(string plain, byte key[], int keySize, byte iv[]);
string CCMMode_Encrypt(string plain, byte key[], int keySize, byte iv[]);
string CCMMode_Decrypt(string plain, byte key[], int keySize, byte iv[]);
} // namespace AES_ED