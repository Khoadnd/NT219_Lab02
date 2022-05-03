#include "../include/AES_Mode.h"

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/modes.h>
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include <cryptopp/xts.h>
using CryptoPP::XTS_Mode;

#include <cryptopp/ccm.h>
using CryptoPP::CCM;

#include <cryptopp/filters.h>
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector; // string to bytes
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <iostream>
using std::cerr;
using std::endl;

namespace AES_ED {

constexpr int tagSize = 8;

string ECBMode_Encrypt(string plain, byte key[], int keySize) {
  string cipher = "";

  try {
    ECB_Mode<AES>::Encryption e;
    e.SetKey(key, keySize);
    StringSource ss(plain, true,
                    new StreamTransformationFilter(e, new StringSink(cipher)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return cipher;
}

string ECBMode_Decrypt(string cipher, byte key[], int keySize) {
  string recovered = "";

  try {
    ECB_Mode<AES>::Decryption d;
    d.SetKey(key, keySize);
    StringSource ss(
        cipher, true,
        new StreamTransformationFilter(d, new StringSink(recovered)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return recovered;
}

string CBCMode_Encrypt(string plain, byte key[], int keySize, byte iv[]) {
  string cipher = "";

  try {
    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, keySize, iv);
    StringSource ss(plain, true,
                    new StreamTransformationFilter(e, new StringSink(cipher)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return cipher;
}

string CBCMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
  string recovered = "";

  try {
    CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, keySize, iv);
    StringSource ss(
        cipher, true,
        new StreamTransformationFilter(d, new StringSink(recovered)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return recovered;
}

string OFBMode_Encrypt(string plain, byte key[], int keySize, byte iv[]) {
  string cipher = "";

  try {
    OFB_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, keySize, iv);
    StringSource ss(plain, true,
                    new StreamTransformationFilter(e, new StringSink(cipher)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return cipher;
}

string OFBMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
  string recovered = "";

  try {
    OFB_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, keySize, iv);
    StringSource ss(
        cipher, true,
        new StreamTransformationFilter(d, new StringSink(recovered)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return recovered;
}

string CFBMode_Encrypt(string plain, byte key[], int keySize, byte iv[]) {
  string cipher = "";

  try {
    CFB_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, keySize, iv);
    StringSource ss(plain, true,
                    new StreamTransformationFilter(e, new StringSink(cipher)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return cipher;
}

string CFBMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
  string recovered = "";

  try {
    CFB_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, keySize, iv);
    StringSource ss(
        cipher, true,
        new StreamTransformationFilter(d, new StringSink(recovered)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return recovered;
}

string CTRMode_Encrypt(string plain, byte key[], int keySize, byte iv[]) {
  string cipher = "";

  try {
    CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, keySize, iv);
    StringSource ss(plain, true,
                    new StreamTransformationFilter(e, new StringSink(cipher)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return cipher;
}

string CTRMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
  string recovered = "";

  try {
    CTR_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, keySize, iv);
    StringSource ss(
        cipher, true,
        new StreamTransformationFilter(d, new StringSink(recovered)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return recovered;
}

string XTSMode_Encrypt(string plain, byte key[], int keySize, byte iv[]) {
  string cipher = "";

  try {
    XTS_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, keySize, iv);
    StringSource ss(plain, true,
                    new StreamTransformationFilter(e, new StringSink(cipher)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return cipher;
}

string XTSMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
  string recovered = "";

  try {
    XTS_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, keySize, iv);
    StringSource ss(
        cipher, true,
        new StreamTransformationFilter(d, new StringSink(recovered)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return recovered;
}

string CCMMode_Encrypt(string plain, byte key[], int keySize, byte iv[]) {
  string cipher = "";

  try {
    CCM<AES, tagSize>::Encryption e;
    e.SetKeyWithIV(key, keySize, iv);
    e.SpecifyDataLengths(0, plain.size(), 0);
    StringSource ss(
        plain, true,
        new AuthenticatedEncryptionFilter(e, new StringSink(cipher)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return cipher;
}

string CCMMode_Decrypt(string cipher, byte key[], int keySize, byte iv[]) {
  string recovered = "";

  try {
    CCM<AES, tagSize>::Decryption d;
    d.SetKeyWithIV(key, keySize, iv);
    d.SpecifyDataLengths(0, cipher.size() - tagSize, 0);
    StringSource ss(
        cipher, true,
        new AuthenticatedDecryptionFilter(d, new StringSink(recovered)));
  } catch (const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    exit(1);
  }

  return recovered;
}
} // namespace AES_ED