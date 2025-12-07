#pragma once

#include <openssl/bn.h>
#include <memory>
#include <string>

namespace rsa {

struct BigNumDeleter {
    void operator()(BIGNUM *bn) const noexcept {
        if (bn != nullptr) {
            BN_free(bn);
        }
    }
};

using BigNumPtr = std::unique_ptr<BIGNUM, BigNumDeleter>;

struct RsaKeyPair {
    BigNumPtr n;
    BigNumPtr e;
    BigNumPtr d;
    BigNumPtr p;
    BigNumPtr q;
    BigNumPtr phi;
    std::size_t key_bits{};

    RsaKeyPair() = default;
    RsaKeyPair(RsaKeyPair &&) noexcept = default;
    RsaKeyPair &operator=(RsaKeyPair &&) noexcept = default;
};

class RsaAlgo {
public:
    static RsaKeyPair generateKeyPair(std::size_t key_bits);

    static BigNumPtr encryptNormal(const BIGNUM *message, const BIGNUM *e, const BIGNUM *n);
    static BigNumPtr encryptSquareMultiply(const BIGNUM *message, const BIGNUM *e, const BIGNUM *n);

    static BigNumPtr decryptNormal(const BIGNUM *cipher, const BIGNUM *d, const BIGNUM *n);
    static BigNumPtr decryptSquareMultiply(const BIGNUM *cipher, const BIGNUM *d, const BIGNUM *n);

    static BigNumPtr messageToInt(const std::string &message);
    static std::string intToMessage(const BIGNUM *value);

private:
    static BigNumPtr makeBigNum();
    static BigNumPtr clone(const BIGNUM *source);

    static BigNumPtr generateRandomBigInt(std::size_t bits);
    static bool isProbablePrime(const BIGNUM *number, int iterations = 10);
    static BigNumPtr generatePrime(std::size_t bits, const BIGNUM *other_prime);

    static BigNumPtr gcd(const BIGNUM *a, const BIGNUM *b);
    static BigNumPtr modInverse(const BIGNUM *a, const BIGNUM *modulus);

    static BigNumPtr modExpNormal(const BIGNUM *base, const BIGNUM *exponent, const BIGNUM *modulus);
    static BigNumPtr modExpSquareAndMultiply(const BIGNUM *base, const BIGNUM *exponent, const BIGNUM *modulus);
};

} // namespace rsa
