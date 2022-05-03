#include "../include/core.h"

#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <iostream>

namespace core {

using CryptoPP::AES;
using CryptoPP::ArraySink;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using std::cin;
using std::cout;
using std::endl;

void GenRandomByte(byte *&out_byte, const int size) {
  AutoSeededRandomPool prng;
  out_byte = new byte[size];
  prng.GenerateBlock(out_byte, size);
}

void GenKey(byte *&key, const int &keySize, byte *&iv, bool &genIV) {
  genIV = false;
  // keySize = DEFAULT_KEYSIZE;

  GenRandomByte(key, keySize);

  cout << "Gen IV? (1/0): ";
  cin >> genIV;

  if (genIV)
    GenRandomByte(iv, AES::BLOCKSIZE);

  cout << "Key: " << PrettyPrint(key, keySize) << endl;
  cout << "Key write down to AES_key.key\n";
  FileSink("AES_key.key", true).Put(key, keySize);

  if (genIV) {
    cout << "IV: " << PrettyPrint(iv, AES::BLOCKSIZE) << endl;
    cout << "IV write down to AES_iv.iv\n";
    FileSink("AES_iv.iv", true).Put(iv, keySize);
  }

  genIV = true;
}

void GetKeyAndIVFromFile(byte *&key, int &keySize, byte *&iv, bool &ivSet) {
  string filename;
  cout << "Enter key file name: ";
  getline(cin, filename);
  keySize = AES::DEFAULT_KEYLENGTH * 2; // * 2 for xts
  key = new byte[keySize];
  FileSource(filename.c_str(), true, new ArraySink(key, keySize));
  cout << "Key: " << PrettyPrint(key, keySize) << endl;

  cout << "Enter IV? (1/0): ";
  cin >> ivSet;

  if (!ivSet)
    return;

  cout << "Enter iv file name: ";
  cin.ignore();
  getline(cin, filename);
  iv = new byte[AES::BLOCKSIZE];
  FileSource(filename.c_str(), true, new ArraySink(iv, AES::BLOCKSIZE));
  cout << "IV: " << PrettyPrint(iv, AES::BLOCKSIZE) << endl;
}

void GetString(string &str) {
  cout << "Enter string: ";
  getline(cin, str);
}

void GetCipherString(string &str) {
  string temp;
  cout << "Enter cipher: ";
  temp.clear();
  getline(cin, temp);
  str.clear();
  StringSource(temp, true, new HexDecoder(new StringSink(str)));
  cout << "Cipher: " << PrettyPrint(str) << endl;
}

void GetStringFromFile(string &str) {
  string fileName;
  cout << "Enter file name: ";
  getline(cin, fileName);
  FileSource(fileName.c_str(), true, new StringSink(str));
  cout << "Readed: " << str << endl;
}

void ReadKeyAndIVFromKeyBoard(byte *&key, int &keySize, byte *&iv,
                              bool &ivSet) {
  string temp;
  bool cont = false;

  // get key
  GetString(temp);
  if (temp.length() < 1 || temp.length() / 2 > AES::MAX_KEYLENGTH) {
    cout << "Invalid key size\n";
    exit(-1);
  }

  key = new byte[temp.length() / 2];
  keySize = temp.length() / 2;
  StringSource(temp, true,
               new HexDecoder(new CryptoPP::ArraySink(key, keySize)));
  cout << "Key: " << PrettyPrint(key, keySize) << endl;

  // get iv
  cout << "Enter IV? (1/0): ";
  cin >> ivSet;
  cin.ignore();
  if (!ivSet)
    return;

  GetString(temp);
  if (temp.length() < 1 || temp.length() > 32) {
    cout << "Invalid iv size\n";
    exit(-1);
  }
  iv = new byte[temp.length() / 2];
  StringSource(temp, true,
               new HexDecoder(new CryptoPP::ArraySink(iv, temp.length() / 2)));
  cout << "IV: " << PrettyPrint(iv, temp.length() / 2) << endl;
}
} // namespace core