#ifndef RSA_HPP
#define RSA_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace rsa {

struct PublicKey {
    uint64_t modulus;
    uint64_t exponent;
};

struct PrivateKey {
    uint64_t modulus;
    uint64_t exponent;
};

class KeyGenerator {
public:
    static PublicKey makePublicKey(uint64_t prime1, uint64_t prime2, uint64_t publicExponent);
    static PrivateKey makePrivateKey(uint64_t prime1, uint64_t prime2, uint64_t publicExponent);

private:
    static uint64_t computeTotient(uint64_t prime1, uint64_t prime2);
    static uint64_t modularInverse(uint64_t value, uint64_t modulus);
    static uint64_t gcd(uint64_t a, uint64_t b);
};

class Cipher {
public:
    static std::vector<uint64_t> encrypt(const std::string &message, const PublicKey &key);
    static std::string decrypt(const std::vector<uint64_t> &ciphertext, const PrivateKey &key);

private:
    static uint64_t modularExponentiation(uint64_t base, uint64_t exponent, uint64_t modulus);
    static void validateKeyModulus(uint64_t modulus);
};

} // namespace rsa

#endif // RSA_HPP
