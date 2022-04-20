#include <iostream>
using std::cout;
using std::endl;
using std::wcin;
using std::wcout;

#include <cstdlib>
using std::exit;

#include <cryptopp/aes.h> // AES
using CryptoPP::AES;

#include <cryptopp/ccm.h> // operation mode
using CryptoPP::CBC_Mode;
using CryptoPP::CCM;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/xts.h>
using CryptoPP::XTS_Mode;

#include <cryptopp/files.h> // Files
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <cryptopp/osrng.h> // Random seed pool
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <cryptopp/filters.h> // Filters
using CryptoPP::Redirector;   // string to bytes
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <string>
using std::string;
using std::wstring;

#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

const string WELCOME =
    (string) "AES Decryption / Encryption with mode of operations\n";
const string MENU = (string) "1. Encrypt.\n2. Decrypt.\n-. Exit.\nChoice: ";
const string MENU_GET_KEY =
    (string) "1. Enter key & iv.\n2. Stored key.\n3. Random key (encryption "
             "only).\n-. Exit.\nChoice: ";
const string MENU_DECRYPT_GET_CIPHERTEXT =
    (string) "1. Input ciphertext.\n2. Read ciphertext from file.\n-. "
             "Exit.\nChoice: ";
const string MENU_ENCRYPT =
    (string) "Mode of operation:\n1. ECB.\n2. CBC\n3. OFB.\n4. CFB.\n5. "
             "CTR\n6. XTS.\n7. CCM.\n-. Exit.\nChoice: ";
const string MENU_ENCRYPT_GET_PLAINTEXT =
    (string) "1. Input plaintext.\n2. Read plaintext from file.\n-. "
             "Exit.\nChoice: ";

struct Key {
  byte key[32];
  byte iv[AES::BLOCKSIZE];

  Key() {
    string filename;
    unsigned int choice = 0;
    std::cout << MENU_GET_KEY;
    std::cin >> choice;
    std::cin.ignore();

    switch (choice) {
    case 1:
      get_key_console();
      break;

    case 2:
      std::cout << "Enter filename: ";
      std::getline(std::cin, filename);
      get_key(filename);
      break;

    case 3:
      gen_key();
      break;

    default:
      break;
    }
  }

  /**
   * @brief Key generated randomly
   *
   */
  void gen_key() {
    AutoSeededRandomPool rng;
    rng.GenerateBlock(key, sizeof(key));
    rng.GenerateBlock(iv, sizeof(iv));
  }

  /**
   * @brief Get key as Hex from console
   *
   */
  void get_key_console() {
    cout << "Not implemented!" << endl;
    exit(0);
  }

  /**
   * @brief Get key from file
   *
   * @param filename
   */
  void get_key(string filename) {
    cout << "Not implemented!" << endl;
    exit(0);
  }
};

string encrypt(Key key, string plain);
string decrypt(Key key, string cipher);
string get_plaintext();
wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);

int main() {
  Key key;
  unsigned int choice = 0;
  std::cout << WELCOME << MENU;
  std::cin >> choice;
  std::cin.ignore();

  switch (choice) {
  case 1:
    encrypt(key, get_plaintext());
    break;
  case 2:
    decrypt(key, get_plaintext());
    break;
  default:
    exit(0);
  }

  return 0;
}

string encrypt(Key key, string plain) {
  string cipher;
  string encoded;
  string filename;
  unsigned int choice = 0;

  std::cout << MENU_ENCRYPT;
  std::cin >> choice;
  std::cin.ignore();

  switch (choice) {
  case 1: { // ECB
    try {
      ECB_Mode<AES>::Encryption e;
      e.SetKey(key.key, sizeof(key.key));
      StringSource s(plain, true,
                     new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 2: { // CBC
    try {
      CBC_Mode<AES>::Encryption e;
      e.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(plain, true,
                     new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 3: { // OFB
    try {
      OFB_Mode<AES>::Encryption e;
      e.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(plain, true,
                     new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 4: { // CFB
    try {
      CFB_Mode<AES>::Encryption e;
      e.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(plain, true,
                     new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 5: { // CTR
    try {
      CTR_Mode<AES>::Encryption e;
      e.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(plain, true,
                     new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 6: { // XTS
    try {
      XTS_Mode<AES>::Encryption e;
      e.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(plain, true,
                     new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 7: { // CCM
    try {
      CCM<AES>::Encryption e;
      e.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(plain, true,
                     new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  default:
    exit(0);
  }
  encoded.clear();
  StringSource(key.key, sizeof(key.key), true,
               new HexEncoder(new StringSink(encoded)));
  std::wcout << "Key: " << string_to_wstring(encoded) << endl;
  encoded.clear();
  StringSource(key.iv, sizeof(key.iv), true,
               new HexEncoder(new StringSink(encoded)));
  std::wcout << "IV: " << string_to_wstring(encoded) << endl;
  encoded.clear();
  StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
  std::wcout << "Cipher: " << string_to_wstring(encoded) << endl;

  return cipher;
}

string decrypt(Key key, string cipher) {
  string plain;
  string encoded;
  string filename;
  unsigned int choice = 0;

  std::cout << MENU_ENCRYPT;
  std::cin >> choice;
  std::cin.ignore();

  switch (choice) {
  case 1: { // ECB
    try {
      ECB_Mode<AES>::Decryption d;
      d.SetKey(key.key, sizeof(key.key));
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d, new StringSink(plain)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 2: { // CBC
    try {
      CBC_Mode<AES>::Decryption d;
      d.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d, new StringSink(plain)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 3: { // OFB
    try {
      OFB_Mode<AES>::Decryption d;
      d.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d, new StringSink(plain)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 4: { // CFB
    try {
      CFB_Mode<AES>::Decryption d;
      d.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d, new StringSink(plain)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 5: { // CTR
    try {
      CTR_Mode<AES>::Decryption d;
      d.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d, new StringSink(plain)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 6: { // XTS
    try {
      XTS_Mode<AES>::Decryption d;
      d.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d, new StringSink(plain)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  case 7: { // CCM
    try {
      CCM<AES>::Decryption d;
      d.SetKeyWithIV(key.key, sizeof(key.key), key.iv);
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d, new StringSink(plain)));
    } catch (const CryptoPP::Exception &e) {
      std::cerr << e.what() << std::endl;
      exit(1);
    }
  } break;

  default:
    exit(0);
  }
  encoded.clear();
  StringSource(key.key, sizeof(key.key), true,
               new HexEncoder(new StringSink(encoded)));
  std::wcout << "Key: " << string_to_wstring(encoded) << endl;
  encoded.clear();
  StringSource(key.iv, sizeof(key.iv), true,
               new HexEncoder(new StringSink(encoded)));
  std::wcout << "IV: " << string_to_wstring(encoded) << endl;
  encoded.clear();
  StringSource(plain, true, new HexEncoder(new StringSink(encoded)));
  std::wcout << "Plain: " << string_to_wstring(encoded) << endl;

  return plain;
}

string get_plaintext() {
  unsigned int choice;
  string plain;
  std::cout << MENU_ENCRYPT_GET_PLAINTEXT;
  std::cin >> choice;
  std::cin.ignore();

  switch (choice) {
  case 1:
    cout << "Enter plaintext: ";
    std::getline(std::cin, plain);
    break;

  case 2:
    cout << "Not implemented!" << endl;
    exit(0);
    // std::cout << "Enter filename: ";
    // std::getline(std::cin, filename);
    // std::ifstream file(filename);
    // std::stringstream buffer;
    // buffer << file.rdbuf();
    // plain = buffer.str();
    break;

  default:
    break;
  }

  return plain;
}

/* convert string to wstring */
wstring string_to_wstring(const std::string &str) {
  wstring_convert<codecvt_utf8<wchar_t>> towstring;
  return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str) {
  wstring_convert<codecvt_utf8<wchar_t>> tostring;
  return tostring.to_bytes(str);
}