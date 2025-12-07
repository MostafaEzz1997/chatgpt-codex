#include "RsaAlgo.hpp"

#include <iostream>
#include <memory>
#include <string>

using namespace rsa;

std::string toHex(const BIGNUM *value) {
    char *hex = BN_bn2hex(value);
    std::string result(hex ? hex : "");
    OPENSSL_free(hex);
    return result;
}

void displayKeyPair(const RsaKeyPair &key) {
    std::cout << "Key size: " << key.key_bits << " bits" << std::endl;
    std::cout << "Modulus (n): " << toHex(key.n.get()) << std::endl;
    std::cout << "Public exponent (e): " << toHex(key.e.get()) << std::endl;
    std::cout << "Private exponent (d): " << toHex(key.d.get()) << std::endl;
    std::cout << "Prime p: " << toHex(key.p.get()) << std::endl;
    std::cout << "Prime q: " << toHex(key.q.get()) << std::endl;
    std::cout << "Euler Totient (phi): " << toHex(key.phi.get()) << std::endl;
}

void runTestCase(std::size_t key_bits, const std::string &message) {
    std::cout << "\n==============================" << std::endl;
    std::cout << "Generating RSA keys with " << key_bits << " bits" << std::endl;
    RsaKeyPair key = RsaAlgo::generateKeyPair(key_bits);

    displayKeyPair(key);

    BigNumPtr messageInt = RsaAlgo::messageToInt(message);
    std::cout << "\nOriginal message: " << message << std::endl;
    std::cout << "Message as integer: " << toHex(messageInt.get()) << std::endl;

    BigNumPtr cipherNormal = RsaAlgo::encryptNormal(messageInt.get(), key.e.get(), key.n.get());
    BigNumPtr cipherSquare = RsaAlgo::encryptSquareMultiply(messageInt.get(), key.e.get(), key.n.get());

    std::cout << "\nCipher (normal mod exp): " << toHex(cipherNormal.get()) << std::endl;
    std::cout << "Cipher (square and multiply): " << toHex(cipherSquare.get()) << std::endl;

    BigNumPtr decryptedNormal = RsaAlgo::decryptNormal(cipherNormal.get(), key.d.get(), key.n.get());
    BigNumPtr decryptedSquare = RsaAlgo::decryptSquareMultiply(cipherSquare.get(), key.d.get(), key.n.get());

    std::cout << "\nDecrypted (normal): " << RsaAlgo::intToMessage(decryptedNormal.get()) << std::endl;
    std::cout << "Decrypted (square and multiply): " << RsaAlgo::intToMessage(decryptedSquare.get()) << std::endl;
}

int main() {
    try {
        runTestCase(512, "Hello RSA!");
        runTestCase(1024, "Another RSA Example");
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
