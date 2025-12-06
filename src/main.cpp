/**
 * @file main.cpp
 * @brief An example program demonstrating the usage of the RSA library.
 */

#include "rsa.hpp"

#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

/**
 * @brief A helper function to print a vector of 64-bit integers to the console.
 * @param label A descriptive label to print before the blocks.
 * @param blocks The vector of numbers to print.
 */
void printBlocks(const std::string &label, const std::vector<uint64_t> &blocks) {
    std::cout << label;
    for (const uint64_t block : blocks) {
        std::cout << ' ' << block;
    }
    std::cout << "\n";
}

/**
 * @brief Runs a full encryption/decryption cycle and prints the results.
 * @param label A descriptive label for the test case.
 * @param message The message to encrypt and then decrypt.
 * @param p A prime number for key generation.
 * @param q A prime number for key generation.
 * @param e The public exponent for key generation.
 */
void runRoundTrip(const std::string &label, const std::string &message, uint64_t p, uint64_t q, uint64_t e) {
    std::cout << "== " << label << " ==\n";
    const auto publicKey = rsa::KeyGenerator::makePublicKey(p, q, e);
    const auto privateKey = rsa::KeyGenerator::makePrivateKey(p, q, e);

    const auto ciphertext = rsa::Cipher::encrypt(message, publicKey);
    printBlocks("Ciphertext blocks:", ciphertext);

    const std::string decrypted = rsa::Cipher::decrypt(ciphertext, privateKey);
    std::cout << "Decrypted: " << decrypted << "\n\n";
}

/**
 * @brief Tests that key generation fails with an invalid public exponent.
 * @param p A prime number for key generation.
 * @param q A prime number for key generation.
 * @param e An invalid public exponent (not coprime with totient).
 */
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

/**
 * @brief Runs a full sign/verify cycle and prints the results.
 * @param label A descriptive label for the test case.
 * @param message The message to sign and then verify.
 * @param p A prime number for key generation.
 * @param q A prime number for key generation.
 * @param e The public exponent for key generation.
 */
void runSignatureRoundTrip(const std::string &label, const std::string &message, uint64_t p, uint64_t q, uint64_t e) {
    std::cout << "== " << label << " ==\n";
    const auto publicKey = rsa::KeyGenerator::makePublicKey(p, q, e);
    const auto privateKey = rsa::KeyGenerator::makePrivateKey(p, q, e);

    std::cout << "Original message: \"" << message << "\"\n";

    // Sign with the private key
    const auto signature = rsa::Cipher::sign(message, privateKey);
    printBlocks("Signature:", signature);

    // Verify with the public key (should succeed)
    const bool is_valid = rsa::Cipher::verify(message, signature, publicKey);
    std::cout << "Verification with correct message: " << (is_valid ? "Success" : "Failure") << "\n";

    // Attempt to verify with a tampered message (should fail)
    const std::string tampered_message = message + " (tampered)";
    const bool is_tampered_valid = rsa::Cipher::verify(tampered_message, signature, publicKey);
    std::cout << "Verification with tampered message: " << (is_tampered_valid ? "Success" : "Failure") << "\n\n";
}

} // namespace

/**
 * @brief Main entry point for the RSA demonstration program.
 * @return 0 on success, 1 on failure.
 */
int main() {
    try {
        runRoundTrip("Short message", "hello", 61, 53, 17);
        runRoundTrip("Punctuation", "RSA demo!", 71, 79, 97);
        runSignatureRoundTrip("Signature Test", "This message is authentic.", 61, 53, 17);
        expectInvalidExponent(61, 53, 9); // 9 shares a factor with totient
    } catch (const std::exception &ex) {
        std::cerr << "Unexpected failure: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
