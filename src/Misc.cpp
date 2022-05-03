#include "../include/core.h"

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <fstream>
#include <iostream>
namespace core {

using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using std::cin;
using std::cout;
using std::fstream;

void WriteStringToFile(const string &str) {
  string fileName;
  cout << "Enter file name: ";
  getline(cin, fileName);
  fstream file;
  file.open(fileName, std::ios::out | std::ios::binary | std::ios::trunc);
  file.write((char *)str.c_str(), str.length());
  file.close();
}

string PrettyPrint(byte arr[], int arraySize) {
  string encoded = "";
  encoded.clear();
  StringSource ss(arr, arraySize, true,
                  new HexEncoder(new StringSink(encoded)));
  return encoded;
}

string PrettyPrint(string text) {
  string encoded = "";
  encoded.clear();
  StringSource ss(text, true, new HexEncoder(new StringSink(encoded)));
  return encoded;
}

} // namespace core