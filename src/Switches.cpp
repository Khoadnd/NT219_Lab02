#include "../include/AES_Mode.h"
#include "../include/core.h"

#include <cryptopp/aes.h>
#include <iostream>

namespace core {

using AES_ED::CBCMode_Decrypt;
using AES_ED::CBCMode_Encrypt;
using AES_ED::CCMMode_Decrypt;
using AES_ED::CCMMode_Encrypt;
using AES_ED::CFBMode_Decrypt;
using AES_ED::CFBMode_Encrypt;
using AES_ED::CTRMode_Decrypt;
using AES_ED::CTRMode_Encrypt;
using AES_ED::ECBMode_Decrypt;
using AES_ED::ECBMode_Encrypt;
using AES_ED::OFBMode_Decrypt;
using AES_ED::OFBMode_Encrypt;
using AES_ED::XTSMode_Decrypt;
using AES_ED::XTSMode_Encrypt;

using std::cin;
using std::cout;
using std::endl;

constexpr int DEFAULT_KEYSIZE = CryptoPP::AES::DEFAULT_KEYLENGTH * 2;

const char *menuMode =
    "1. ECB\n2. CBC\n3. OFB\n4. CFB\n5. CTR\n6. XTS\n7. CCM\n";
const char *menuGetKey = "1. Generate key\n2. Use key\n3. Enter key\n";
const char *menuGetText =
    "Get plain/cipher text\n1. Enter from console\n2. Use file\n";

void SwitchGetString(string &str) {
  int choice;
  cout << menuGetText;
  cin >> choice;
  cin.ignore();

  switch (choice) {
  case 1: {
    GetString(str);
    break;
  }
  case 2: {
    GetStringFromFile(str);
    break;
  }
  }
}

void SwitchGetStringCipher(string &str) {
  int choice;
  cout << menuGetText;
  cin >> choice;
  cin.ignore();

  switch (choice) { // get cipher
  case 1: {
    GetCipherString(str);
    break;
  }
  case 2: {
    GetStringFromFile(str);
    break;
  }
  }
}

void SwitchGetKeyAndIV(byte *&key, int &keySize, byte *&iv, bool &ivSet) {
  int choice;
  cout << menuGetKey;
  cin >> choice;
  cin.ignore();

  switch (choice) { // get key
  case 1: {
    keySize = DEFAULT_KEYSIZE;
    GenKey(key, keySize, iv, ivSet);
    break;
  }
  case 2: {
    GetKeyAndIVFromFile(key, keySize, iv, ivSet);
    break;
  }
  case 3: {
    ReadKeyAndIVFromKeyBoard(key, keySize, iv, ivSet);
    break;
  }
  }
}

void SwitchEncrypt(string &cipher, string &plain, byte *key, int keySize,
                   byte *iv, bool ivSet) {
  int choice;
  cout << menuMode;
  cin >> choice;

  switch (choice) { // choice mode of operation
  case 1:
    cipher = ECBMode_Encrypt(plain, key, keySize);
    cout << "Cipher: " << PrettyPrint(cipher) << endl;
    break;

  case 2:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    cipher = CBCMode_Encrypt(plain, key, keySize, iv);
    cout << "Cipher: " << PrettyPrint(cipher) << endl;
    break;

  case 3:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    cipher = OFBMode_Encrypt(plain, key, keySize, iv);
    cout << "Cipher: " << PrettyPrint(cipher) << endl;
    break;

  case 4:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    cipher = CFBMode_Encrypt(plain, key, keySize, iv);
    cout << "Cipher: " << PrettyPrint(cipher) << endl;
    break;

  case 5:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    cipher = CTRMode_Encrypt(plain, key, keySize, iv);
    cout << "Cipher: " << PrettyPrint(cipher) << endl;
    break;

  case 6:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    cipher = XTSMode_Encrypt(plain, key, keySize, iv);
    cout << "Cipher: " << PrettyPrint(cipher) << endl;
    break;

  case 7:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    cipher = CCMMode_Encrypt(plain, key, keySize, iv);
    cout << "Cipher: " << PrettyPrint(cipher) << endl;
    break;

  default:
    break;
  }
}

void SwitchDecrypt(string &plain, string &cipher, byte *key, int keySize,
                   byte *iv, bool ivSet) {
  int choice;
  cout << menuMode;
  cin >> choice;
  switch (choice) { // choice mode of operation
  case 1:
    plain = ECBMode_Decrypt(cipher, key, keySize);
    cout << "Plain: " << plain << endl;
    break;

  case 2:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    plain = CBCMode_Decrypt(cipher, key, keySize, iv);
    cout << "Plain: " << plain << endl;
    break;

  case 3:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    plain = OFBMode_Decrypt(cipher, key, keySize, iv);
    cout << "Plain: " << plain << endl;
    break;

  case 4:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    plain = CFBMode_Decrypt(cipher, key, keySize, iv);
    cout << "Plain: " << plain << endl;
    break;

  case 5:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    plain = CTRMode_Decrypt(cipher, key, keySize, iv);
    cout << "Plain: " << plain << endl;
    break;

  case 6:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    plain = XTSMode_Decrypt(cipher, key, keySize, iv);
    cout << "Plain: " << plain << endl;
    break;

  case 7:
    if (!ivSet) {
      cout << "No IV set" << endl;
      break;
    }
    plain = CCMMode_Decrypt(cipher, key, keySize, iv);
    cout << "Plain: " << plain << endl;
    break;

  default:
    break;
  }
}
} // namespace core