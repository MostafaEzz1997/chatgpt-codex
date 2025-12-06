/**
 * @file main.cpp
 * @brief Demonstrates RSA key generation, encryption/decryption, and signing/verification.
 */

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "RsaAlgo.hpp"

void RunEncryptionTest(RsaAlgo &rsa, unsigned int bits) {
    std::cout << "\n=== Encryption/Decryption Test for " << bits << "-bit key ===" << std::endl;
    auto keys = rsa.GenerateKeys(bits);
    std::string message = "Hello RSA " + std::to_string(bits);
    size_t max_bytes = std::max<size_t>(1, bits / 8 - 1);
    if (message.size() > max_bytes) {
        message.resize(max_bytes);
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> ciphertext(rsa.Encrypt(message, keys), BN_free);
    auto decrypted = rsa.Decrypt(ciphertext.get(), keys);

    std::cout << "Original : " << message << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << (message == decrypted ? "Result   : success" : "Result   : failure") << std::endl;
}

void RunSignatureTest(RsaAlgo &rsa, unsigned int bits) {
    std::cout << "\n=== Signature Test for " << bits << "-bit key ===" << std::endl;
    auto keys = rsa.GenerateKeys(bits);
    std::string message = "Signature test " + std::to_string(bits);
    size_t max_bytes = std::max<size_t>(1, bits / 8 - 1);
    if (message.size() > max_bytes) {
        message.resize(max_bytes);
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> signature(rsa.Sign(message, keys), BN_free);
    bool verified = rsa.Verify(message, signature.get(), keys);

    std::cout << "Message  : " << message << std::endl;
    char *sig_hex = BN_bn2hex(signature.get());
    std::cout << "Signature: " << sig_hex << std::endl;
    OPENSSL_free(sig_hex);
    std::cout << (verified ? "Result   : verified" : "Result   : failed") << std::endl;
}

int main() {
    RsaAlgo rsa;
    std::vector<unsigned int> bit_lengths = {128, 1024, 2048, 4096};

    for (auto bits : bit_lengths) {
        RunEncryptionTest(rsa, bits);
        RunSignatureTest(rsa, bits);
    }

    return 0;
}
