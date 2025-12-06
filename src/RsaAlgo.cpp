#include "RsaAlgo.hpp"
#include <algorithm>
#include <chrono>
#include <limits>
#include <stdexcept>

RsaAlgo::RsaAlgo(unsigned int prime_checks)
    : _prime_checks(prime_checks),
      _rng(static_cast<std::mt19937_64::result_type>(std::chrono::high_resolution_clock::now().time_since_epoch().count())) {}

RsaAlgo::KeyPair RsaAlgo::GenerateKeys(unsigned int key_bits, unsigned int min_delta_bytes) {
    if (key_bits < 64) {
        throw std::invalid_argument("Key size too small");
    }

    auto primes = GeneratePrimePair(key_bits / 2, min_delta_bytes);
    BN_ptr &p = primes.first;
    BN_ptr &q = primes.second;

    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BN_ptr n(BN_new(), BN_free);
    BN_ptr phi(BN_new(), BN_free);
    BN_ptr p_minus(BN_dup(p.get()), BN_free);
    BN_ptr q_minus(BN_dup(q.get()), BN_free);

    BN_mul(n.get(), p.get(), q.get(), ctx.get());
    BN_sub(p_minus.get(), p.get(), BN_value_one());
    BN_sub(q_minus.get(), q.get(), BN_value_one());
    BN_mul(phi.get(), p_minus.get(), q_minus.get(), ctx.get());

    BN_ptr e(BN_new(), BN_free);
    BN_set_word(e.get(), 65537);

    BN_ptr gcd(BN_new(), BN_free);
    BN_gcd(gcd.get(), e.get(), phi.get(), ctx.get());
    if (!BN_is_one(gcd.get())) {
        std::uniform_int_distribution<uint64_t> dist(3, std::numeric_limits<uint64_t>::max());
        do {
            BN_set_word(e.get(), dist(_rng) | 1ULL);
            BN_gcd(gcd.get(), e.get(), phi.get(), ctx.get());
        } while (!BN_is_one(gcd.get()));
    }

    BN_ptr d(BN_mod_inverse(nullptr, e.get(), phi.get(), ctx.get()), BN_free);
    if (!d) {
        throw std::runtime_error("Failed to compute modular inverse");
    }

    return {ToHex(n.get()), ToHex(e.get()), ToHex(d.get()), ToHex(p.get()), ToHex(q.get())};
}

BIGNUM* RsaAlgo::Encrypt(const std::string &message, const KeyPair &public_key) {
    BN_ptr m = BytesToBigNum(std::vector<uint8_t>(message.begin(), message.end()));
    BN_ptr n = LoadFromHex(public_key.n);
    BN_ptr e = LoadFromHex(public_key.e);

    if (BN_cmp(m.get(), n.get()) >= 0) {
        throw std::invalid_argument("Message too large for modulus");
    }

    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr out(BN_new(), BN_free);
    BN_mod_exp(out.get(), m.get(), e.get(), n.get(), ctx.get());
    return out.release();
}

std::string RsaAlgo::Decrypt(const BIGNUM *ciphertext, const KeyPair &private_key) {
    BN_ptr c(BN_dup(ciphertext), BN_free);
    BN_ptr n = LoadFromHex(private_key.n);
    BN_ptr d = LoadFromHex(private_key.d);

    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr m(BN_new(), BN_free);
    BN_mod_exp(m.get(), c.get(), d.get(), n.get(), ctx.get());
    auto bytes = BigNumToBytes(m.get());
    return std::string(bytes.begin(), bytes.end());
}

BIGNUM* RsaAlgo::Sign(const std::string &message, const KeyPair &private_key) {
    BN_ptr m = BytesToBigNum(std::vector<uint8_t>(message.begin(), message.end()));
    BN_ptr n = LoadFromHex(private_key.n);
    BN_ptr d = LoadFromHex(private_key.d);

    if (BN_cmp(m.get(), n.get()) >= 0) {
        throw std::invalid_argument("Message too large for modulus");
    }

    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr sig(BN_new(), BN_free);
    BN_mod_exp(sig.get(), m.get(), d.get(), n.get(), ctx.get());
    return sig.release();
}

bool RsaAlgo::Verify(const std::string &message, const BIGNUM *signature, const KeyPair &public_key) {
    BN_ptr sig(BN_dup(signature), BN_free);
    BN_ptr n = LoadFromHex(public_key.n);
    BN_ptr e = LoadFromHex(public_key.e);

    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr recovered(BN_new(), BN_free);
    BN_mod_exp(recovered.get(), sig.get(), e.get(), n.get(), ctx.get());

    auto expected = BytesToBigNum(std::vector<uint8_t>(message.begin(), message.end()));
    return BN_cmp(recovered.get(), expected.get()) == 0;
}

RsaAlgo::BN_ptr RsaAlgo::GeneratePrime(unsigned int bits) {
    BN_ptr prime(BN_new(), BN_free);
    CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
    while (true) {
        BN_rand(prime.get(), bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        int is_prime = BN_is_prime_ex(prime.get(), _prime_checks, ctx.get(), nullptr);
        if (is_prime == 1) {
            return prime;
        }
    }
}

std::pair<RsaAlgo::BN_ptr, RsaAlgo::BN_ptr> RsaAlgo::GeneratePrimePair(unsigned int bits, unsigned int min_delta_bytes) {
    BN_ptr p = GeneratePrime(bits);
    BN_ptr q = GeneratePrime(bits);

    BN_ptr delta(BN_new(), BN_free);
    BN_set_word(delta.get(), min_delta_bytes);

    BN_ptr diff(BN_new(), BN_free);

    while (true) {
        int cmp = BN_cmp(p.get(), q.get());
        if (cmp > 0) {
            BN_sub(diff.get(), p.get(), q.get());
        } else if (cmp < 0) {
            BN_sub(diff.get(), q.get(), p.get());
        } else {
            BN_zero(diff.get());
        }

        if (cmp != 0 && BN_cmp(diff.get(), delta.get()) >= 0) {
            break;
        }

        q = GeneratePrime(bits);
    }

    return {std::move(p), std::move(q)};
}

RsaAlgo::BN_ptr RsaAlgo::BytesToBigNum(const std::vector<uint8_t> &bytes) {
    BN_ptr value(BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr), BN_free);
    if (!value) {
        throw std::runtime_error("Failed to convert bytes to BIGNUM");
    }
    return value;
}

std::vector<uint8_t> RsaAlgo::BigNumToBytes(const BIGNUM *value) {
    int size = BN_num_bytes(value);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    BN_bn2bin(value, bytes.data());
    return bytes;
}

RsaAlgo::BN_ptr RsaAlgo::LoadFromHex(const std::string &hex) {
    BIGNUM *raw = nullptr;
    if (BN_hex2bn(&raw, hex.c_str()) == 0) {
        throw std::runtime_error("Failed to parse hex BIGNUM");
    }
    return BN_ptr(raw, BN_free);
}

std::string RsaAlgo::ToHex(const BIGNUM *value) {
    char *hex = BN_bn2hex(value);
    if (!hex) {
        throw std::runtime_error("Failed to convert BIGNUM to hex");
    }
    std::string out(hex);
    OPENSSL_free(hex);
    return out;
}
