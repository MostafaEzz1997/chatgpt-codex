#include "rsa.hpp"

#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void printCipher(const std::vector<uint64_t> &ciphertext) {
    std::cout << "Ciphertext blocks:";
    for (const uint64_t block : ciphertext) {
        std::cout << ' ' << block;
    }
    std::cout << "\n";
}

void runRoundTrip(const std::string &label, const std::string &message, uint64_t p, uint64_t q, uint64_t e) {
    std::cout << "== " << label << " ==\n";
    const auto publicKey = rsa::KeyGenerator::makePublicKey(p, q, e);
    const auto privateKey = rsa::KeyGenerator::makePrivateKey(p, q, e);

    const auto ciphertext = rsa::Cipher::encrypt(message, publicKey);
    printCipher(ciphertext);

    const std::string decrypted = rsa::Cipher::decrypt(ciphertext, privateKey);
    std::cout << "Decrypted: " << decrypted << "\n\n";
}

void expectInvalidExponent(uint64_t p, uint64_t q, uint64_t e) {
    std::cout << "== Invalid exponent scenario ==\n";
    try {
        auto badKey = rsa::KeyGenerator::makePublicKey(p, q, e);
        (void)badKey;
        std::cout << "Unexpected success when constructing invalid key\n\n";
    } catch (const std::invalid_argument &ex) {
        std::cout << "Caught expected failure: " << ex.what() << "\n\n";
    }
}

} // namespace

int main() {
    try {
        runRoundTrip("Short message", "hello", 61, 53, 17);
        runRoundTrip("Punctuation", "RSA demo!", 71, 79, 97);
        expectInvalidExponent(61, 53, 9); // 9 shares a factor with totient
    } catch (const std::exception &ex) {
        std::cerr << "Unexpected failure: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
