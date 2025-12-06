/**
 * @file rsa.cpp
 * @brief Implements the RSA encryption and signature library functions.
 */

#include "rsa.hpp"

#include <limits>

namespace rsa {

namespace {
/// The maximum value for a standard ASCII character (and extended ASCII).
constexpr uint64_t kAsciiLimit = 255;
}

PublicKey KeyGenerator::makePublicKey(uint64_t prime1, uint64_t prime2, uint64_t publicExponent) {
    const uint64_t modulus = prime1 * prime2;
    const uint64_t totient = computeTotient(prime1, prime2);

    if (gcd(publicExponent, totient) != 1) {
        throw std::invalid_argument("Public exponent must be coprime with totient");
    }

    return PublicKey{modulus, publicExponent};
}

PrivateKey KeyGenerator::makePrivateKey(uint64_t prime1, uint64_t prime2, uint64_t publicExponent) {
    const uint64_t modulus = prime1 * prime2;
    const uint64_t totient = computeTotient(prime1, prime2);

    if (gcd(publicExponent, totient) != 1) {
        throw std::invalid_argument("Public exponent must be coprime with totient");
    }

    const uint64_t privateExponent = modularInverse(publicExponent, totient);
    return PrivateKey{modulus, privateExponent};
}

uint64_t KeyGenerator::computeTotient(uint64_t prime1, uint64_t prime2) {
    return (prime1 - 1) * (prime2 - 1);
}

uint64_t KeyGenerator::modularInverse(uint64_t value, uint64_t modulus) {
    int64_t t = 0, new_t = 1;
    int64_t r = static_cast<int64_t>(modulus);
    int64_t new_r = static_cast<int64_t>(value);

    while (new_r != 0) {
        const int64_t quotient = r / new_r;
        const int64_t temp_t = t - quotient * new_t;
        t = new_t;
        new_t = temp_t;

        const int64_t temp_r = r - quotient * new_r;
        r = new_r;
        new_r = temp_r;
    }

    if (r > 1) {
        throw std::invalid_argument("Value is not invertible");
    }

    if (t < 0) {
        t += static_cast<int64_t>(modulus);
    }

    return static_cast<uint64_t>(t);
}

uint64_t KeyGenerator::gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        const uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

std::vector<uint64_t> Cipher::encrypt(const std::string &message, const PublicKey &key) {
    validateKeyModulus(key.modulus);

    std::vector<uint64_t> ciphertext;
    ciphertext.reserve(message.size());

    for (const unsigned char ch : message) {
        const uint64_t encoded = modularExponentiation(static_cast<uint64_t>(ch), key.exponent, key.modulus);
        ciphertext.push_back(encoded);
    }

    return ciphertext;
}

std::string Cipher::decrypt(const std::vector<uint64_t> &ciphertext, const PrivateKey &key) {
    validateKeyModulus(key.modulus);

    std::string plaintext;
    plaintext.reserve(ciphertext.size());

    for (const uint64_t chunk : ciphertext) {
        const uint64_t decoded = modularExponentiation(chunk, key.exponent, key.modulus);

        if (decoded > kAsciiLimit) {
            throw std::runtime_error("Decrypted value exceeds ASCII limit");
        }

        plaintext.push_back(static_cast<char>(decoded));
    }

    return plaintext;
}

std::vector<uint64_t> Cipher::sign(const std::string &message, const PrivateKey &key) {
    validateKeyModulus(key.modulus);

    std::vector<uint64_t> signature;
    signature.reserve(message.size());

    for (const unsigned char ch : message) {
        const uint64_t signed_char = modularExponentiation(static_cast<uint64_t>(ch), key.exponent, key.modulus);
        signature.push_back(signed_char);
    }

    return signature;
}

bool Cipher::verify(const std::string &message, const std::vector<uint64_t> &signature, const PublicKey &key) {
    if (message.length() != signature.size()) {
        return false;
    }

    const std::string decrypted_signature_str = decrypt(signature, PrivateKey{key.modulus, key.exponent});

    return message == decrypted_signature_str;
}

uint64_t Cipher::modularExponentiation(uint64_t base, uint64_t exponent, uint64_t modulus) {
    if (modulus == 1) {
        return 0;
    }

    uint64_t result = 1;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;
        }
        exponent >>= 1;
        base = (base * base) % modulus;
    }

    return result;
}

void Cipher::validateKeyModulus(uint64_t modulus) {
    if (modulus <= kAsciiLimit) {
        throw std::invalid_argument("Modulus must be greater than 255 to encode ASCII characters");
    }
}

} // namespace rsa
