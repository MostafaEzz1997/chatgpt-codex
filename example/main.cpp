#include "RsaAlgo.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <utility>

using namespace rsa;

std::string toHex(const BIGNUM *value) {
    char *hex = BN_bn2hex(value);
    std::string result(hex ? hex : "");
    OPENSSL_free(hex);
    return result;
}

template <typename Func>
auto timeOperation(Func &&func) {
    const auto start = std::chrono::high_resolution_clock::now();
    auto result = func();
    const auto end = std::chrono::high_resolution_clock::now();
    const double elapsedMs =
        std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - start).count();
    return std::pair<decltype(result), double>{std::move(result), elapsedMs};
}

void printKeyInfo(const RsaKeyPair &key) {
    std::cout << "Key size : " << key.key_bits << " bits" << std::endl;
    std::cout << "Public exponent (e): " << toHex(key.e.get()) << std::endl;
    std::cout << "Private exponent (d): " << toHex(key.d.get()) << std::endl;
    std::cout << "Modulus (n): " << toHex(key.n.get()) << std::endl;
}

void runEncryptionDecryption(const RsaKeyPair &key, const std::string &message) {
    std::cout << "\n=== Encryption/Decryption Test for " << key.key_bits << "-bit key ===" << std::endl;
    printKeyInfo(key);

    BigNumPtr messageInt = RsaAlgo::messageToInt(message);
    const auto [cipher, encryptMs] =
        timeOperation([&] { return RsaAlgo::encryptSquareMultiply(messageInt.get(), key.e.get(), key.n.get()); });
    const auto [decrypted, decryptMs] =
        timeOperation([&] { return RsaAlgo::decryptSquareMultiply(cipher.get(), key.d.get(), key.n.get()); });

    std::cout << "Original : " << message << std::endl;
    std::cout << "Cipher   : " << toHex(cipher.get()) << std::endl;
    std::cout << "Decrypted: " << RsaAlgo::intToMessage(decrypted.get()) << std::endl;
    std::cout << "Result   : "
              << (message == RsaAlgo::intToMessage(decrypted.get()) ? "success" : "failure") << std::endl;
    std::cout << "Encryption time (ms): " << encryptMs << std::endl;
    std::cout << "Decryption time (ms): " << decryptMs << std::endl;
}

void runSignature(const RsaKeyPair &key, const std::string &message) {
    std::cout << "\n=== Signature Test for " << key.key_bits << "-bit key ===" << std::endl;
    printKeyInfo(key);

    BigNumPtr messageInt = RsaAlgo::messageToInt(message);
    const auto [signature, signMs] =
        timeOperation([&] { return RsaAlgo::signMessage(messageInt.get(), key.d.get(), key.n.get()); });
    const auto [verified, verifyMs] = timeOperation(
        [&] { return RsaAlgo::verifySignature(signature.get(), messageInt.get(), key.e.get(), key.n.get()); });

    std::cout << "Message  : " << message << std::endl;
    std::cout << "Signature: " << toHex(signature.get()) << std::endl;
    std::cout << "Result   : " << (verified ? "verified" : "failed") << std::endl;
    std::cout << "Signature time (ms): " << signMs << std::endl;
    std::cout << "Verification time (ms): " << verifyMs << std::endl;
}

int main() {
    try {
        RsaKeyPair key128 = RsaAlgo::generateKeyPair(128);
        runEncryptionDecryption(key128, "Hello RSA 128");
        runSignature(key128, "Signature test ");

        RsaKeyPair key1024 = RsaAlgo::generateKeyPair(1024);
        runEncryptionDecryption(key1024, "Hello RSA 1024");
        runSignature(key1024, "Signature test 1024");

        RsaKeyPair key2048 = RsaAlgo::generateKeyPair(2048);
        runEncryptionDecryption(key2048, "Hello RSA 2048");
        runSignature(key2048, "Signature test 2048");

        RsaKeyPair key4096 = RsaAlgo::generateKeyPair(4096);
        runEncryptionDecryption(key4096, "Hello RSA 4096");
        runSignature(key4096, "Signature test 4096");
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
