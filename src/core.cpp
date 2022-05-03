#include "../include/core.h"

#include <iostream>

namespace core {

using std::cin;
using std::cout;

void Encrypt() {
  int keySize = 0;
  int choiceGet = 0;
  bool ivSet = false;
  string plain = "";
  string cipher = "";
  byte *key = nullptr;
  byte *iv = nullptr;

  SwitchGetString(plain);
  SwitchGetKeyAndIV(key, keySize, iv, ivSet);
  SwitchEncrypt(cipher, plain, key, keySize, iv, ivSet);

  bool writeToFile = false;
  cout << "Write cipher to file? (1/0): ";
  cin >> writeToFile;
  cin.ignore();

  if (writeToFile)
    WriteStringToFile(cipher);
}

void Decrypt() {
  int keySize = 0;
  int choiceGet = 0;
  bool ivSet = false;
  string plain = "";
  string cipher = "";
  byte *key = nullptr;
  byte *iv = nullptr;

  SwitchGetStringCipher(cipher);
  SwitchGetKeyAndIV(key, keySize, iv, ivSet);
  SwitchDecrypt(plain, cipher, key, keySize, iv, ivSet);

  bool writeToFile = false;
  cout << "Write plain to file? (1/0): ";
  cin >> writeToFile;
  cin.ignore();
  if (writeToFile)
    WriteStringToFile(plain);
}
}