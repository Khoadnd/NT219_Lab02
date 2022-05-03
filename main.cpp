#include "include/core.h"
using namespace core;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

const char *menu = "1. Encrypt\n2. Decrypt\n3. Exit\n";

int main() {
  int choice;
  cout << menu;
  cin >> choice;
  cin.ignore();

  switch (choice) {
  case 1: // Encrypt
    Encrypt();
    break;

  case 2: // Decrypt
    Decrypt();
    break;

  default:
    break;
  }
  return 0;
}