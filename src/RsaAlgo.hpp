#ifndef _RSAALGO_HPP_
#define _RSAALGO_HPP_

#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/rand.h>

/**
 * @class RsaAlgo
 * @brief Implements RSA key generation, encryption, decryption, signing, and verification.
 */
class RsaAlgo {
public:
    struct KeyPair {
        std::string n;
        std::string e;
        std::string d;
        std::string p;
        std::string q;
    };

    explicit RsaAlgo(unsigned int prime_checks = 16);

    KeyPair GenerateKeys(unsigned int key_bits, unsigned int min_delta_bytes = 256);

    BIGNUM* Encrypt(const std::string &message, const KeyPair &public_key);
    std::string Decrypt(const BIGNUM *ciphertext, const KeyPair &private_key);

    BIGNUM* Sign(const std::string &message, const KeyPair &private_key);
    bool Verify(const std::string &message, const BIGNUM *signature, const KeyPair &public_key);

private:
    unsigned int _prime_checks;
    std::mt19937_64 _rng;

    using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

    BN_ptr GeneratePrime(unsigned int bits);
    std::pair<BN_ptr, BN_ptr> GeneratePrimePair(unsigned int bits, unsigned int min_delta_bytes);
    BN_ptr BytesToBigNum(const std::vector<uint8_t> &bytes);
    std::vector<uint8_t> BigNumToBytes(const BIGNUM *value);

    BN_ptr LoadFromHex(const std::string &hex);
    std::string ToHex(const BIGNUM *value);
};

#endif // _RSAALGO_HPP_
