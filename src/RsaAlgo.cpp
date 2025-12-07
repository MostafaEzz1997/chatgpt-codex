#include "RsaAlgo.hpp"

#include <chrono>
#include <random>
#include <stdexcept>

namespace rsa {
namespace {
constexpr std::size_t MIN_KEY_BITS = 128;
constexpr std::size_t MAX_KEY_BITS = 4096;

BigNumPtr makeInitialized() {
    BigNumPtr bn(BN_new());
    if (!bn) {
        throw std::runtime_error("Failed to allocate BIGNUM");
    }
    return bn;
}

} // namespace

BigNumPtr RsaAlgo::makeBigNum() {
    return makeInitialized();
}

BigNumPtr RsaAlgo::clone(const BIGNUM *source) {
    BigNumPtr result = makeInitialized();
    if (!BN_copy(result.get(), source)) {
        throw std::runtime_error("Failed to copy BIGNUM");
    }
    return result;
}

BigNumPtr RsaAlgo::generateRandomBigInt(std::size_t bits) {
    if (bits == 0) {
        return makeBigNum();
    }

    std::random_device rd;
    std::mt19937_64 gen(rd());

    std::size_t byteLength = (bits + 7) / 8;
    std::string buffer(byteLength, '\0');
    for (std::size_t i = 0; i < byteLength; ++i) {
        buffer[i] = static_cast<char>(gen() & 0xFF);
    }
    buffer[0] |= static_cast<char>(0x80);

    BigNumPtr bn = makeInitialized();
    BN_bin2bn(reinterpret_cast<const unsigned char *>(buffer.data()), static_cast<int>(buffer.size()), bn.get());

    int shift = static_cast<int>((byteLength * 8) - bits);
    if (shift > 0) {
        BN_rshift(bn.get(), bn.get(), shift);
    }
    BN_set_bit(bn.get(), static_cast<int>(bits - 1));
    return bn;
}

BigNumPtr RsaAlgo::gcd(const BIGNUM *a, const BIGNUM *b) {
    BigNumPtr x = clone(a);
    BigNumPtr y = clone(b);
    BigNumPtr mod = makeInitialized();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    while (!BN_is_zero(y.get())) {
        BN_div(nullptr, mod.get(), x.get(), y.get(), ctx);
        BN_copy(x.get(), y.get());
        BN_copy(y.get(), mod.get());
    }
    BN_CTX_free(ctx);
    return x;
}

bool RsaAlgo::isProbablePrime(const BIGNUM *number, int iterations) {
    if (BN_is_negative(number) || BN_is_zero(number) || BN_is_one(number)) {
        return false;
    }

    if (!BN_is_odd(number)) {
        return false;
    }

    BigNumPtr n_minus_one = clone(number);
    BN_sub_word(n_minus_one.get(), 1);

    BigNumPtr d = clone(n_minus_one.get());
    unsigned int s = 0;
    while (!BN_is_zero(d.get()) && !BN_is_bit_set(d.get(), 0)) {
        BN_rshift1(d.get(), d.get());
        ++s;
    }

    std::mt19937_64 gen(static_cast<unsigned long long>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<unsigned long long> dist;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BigNumPtr a = makeInitialized();
    BigNumPtr x = makeInitialized();
    BigNumPtr n_sub_two = clone(number);
    BN_sub_word(n_sub_two.get(), 2);

    for (int i = 0; i < iterations; ++i) {
        BN_set_word(a.get(), 2 + (dist(gen) % BN_get_word(n_sub_two.get())));
        x = modExpSquareAndMultiply(a.get(), d.get(), number);
        if (BN_is_one(x.get()) || BN_cmp(x.get(), n_minus_one.get()) == 0) {
            continue;
        }

        bool continueLoop = false;
        for (unsigned int r = 1; r < s; ++r) {
            BN_mod_mul(x.get(), x.get(), x.get(), number, ctx);
            if (BN_cmp(x.get(), n_minus_one.get()) == 0) {
                continueLoop = true;
                break;
            }
        }
        if (continueLoop) {
            continue;
        }
        BN_CTX_free(ctx);
        return false;
    }

    BN_CTX_free(ctx);
    return true;
}

BigNumPtr RsaAlgo::generatePrime(std::size_t bits, const BIGNUM *other_prime) {
    if (bits < 4) {
        throw std::runtime_error("Prime size too small");
    }

    BigNumPtr candidate = makeInitialized();
    BigNumPtr difference = makeInitialized();
    BigNumPtr minDistance = makeInitialized();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BN_one(minDistance.get());
    unsigned int distanceBits = static_cast<unsigned int>(std::max<std::size_t>(1, std::min<std::size_t>(bits - 4, 256)));
    BN_lshift(minDistance.get(), minDistance.get(), distanceBits);

    while (true) {
        candidate = generateRandomBigInt(bits);
        if (!BN_is_odd(candidate.get())) {
            BN_add_word(candidate.get(), 1);
        }

        if (other_prime && !BN_is_zero(other_prime)) {
            BN_sub(difference.get(), candidate.get(), other_prime);
            if (BN_is_negative(difference.get())) {
                BN_sub(difference.get(), other_prime, candidate.get());
            }
            if (BN_cmp(difference.get(), minDistance.get()) < 0) {
                continue;
            }
        }

        if (isProbablePrime(candidate.get())) {
            BN_CTX_free(ctx);
            return candidate;
        }
    }
}

BigNumPtr RsaAlgo::modInverse(const BIGNUM *a, const BIGNUM *modulus) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BigNumPtr t = makeInitialized();
    BigNumPtr new_t = makeInitialized();
    BigNumPtr r = clone(modulus);
    BigNumPtr new_r = clone(a);

    BN_zero(t.get());
    BN_one(new_t.get());

    BigNumPtr quotient = makeInitialized();
    BigNumPtr temp = makeInitialized();

    while (!BN_is_zero(new_r.get())) {
        BN_div(quotient.get(), nullptr, r.get(), new_r.get(), ctx);

        BN_mul(temp.get(), quotient.get(), new_t.get(), ctx);
        BN_sub(temp.get(), t.get(), temp.get());
        BN_copy(t.get(), new_t.get());
        BN_copy(new_t.get(), temp.get());

        BN_mul(temp.get(), quotient.get(), new_r.get(), ctx);
        BN_sub(temp.get(), r.get(), temp.get());
        BN_copy(r.get(), new_r.get());
        BN_copy(new_r.get(), temp.get());
    }

    if (BN_cmp(r.get(), BN_value_one()) > 0) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Modular inverse does not exist");
    }

    if (BN_is_negative(t.get())) {
        BN_add(t.get(), t.get(), modulus);
    }

    BN_CTX_free(ctx);
    return t;
}

BigNumPtr RsaAlgo::modExpNormal(const BIGNUM *base, const BIGNUM *exponent, const BIGNUM *modulus) {
    if (BN_is_zero(modulus)) {
        return makeBigNum();
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BigNumPtr result = makeInitialized();
    BigNumPtr baseCopy = clone(base);
    BigNumPtr expCopy = clone(exponent);

    BN_one(result.get());
    BN_mod(baseCopy.get(), baseCopy.get(), modulus, ctx);

    while (!BN_is_zero(expCopy.get())) {
        if (BN_is_odd(expCopy.get())) {
            BN_mod_mul(result.get(), result.get(), baseCopy.get(), modulus, ctx);
        }
        BN_rshift1(expCopy.get(), expCopy.get());
        BN_mod_mul(baseCopy.get(), baseCopy.get(), baseCopy.get(), modulus, ctx);
    }

    BN_CTX_free(ctx);
    return result;
}

BigNumPtr RsaAlgo::modExpSquareAndMultiply(const BIGNUM *base, const BIGNUM *exponent, const BIGNUM *modulus) {
    if (BN_is_zero(modulus)) {
        return makeBigNum();
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BigNumPtr result = makeInitialized();
    BigNumPtr baseCopy = clone(base);

    BN_one(result.get());
    BN_mod(baseCopy.get(), baseCopy.get(), modulus, ctx);

    int bits = BN_num_bits(exponent);
    for (int i = bits - 1; i >= 0; --i) {
        BN_mod_mul(result.get(), result.get(), result.get(), modulus, ctx);
        if (BN_is_bit_set(exponent, i)) {
            BN_mod_mul(result.get(), result.get(), baseCopy.get(), modulus, ctx);
        }
    }

    BN_CTX_free(ctx);
    return result;
}

BigNumPtr RsaAlgo::encryptNormal(const BIGNUM *message, const BIGNUM *e, const BIGNUM *n) {
    if (BN_cmp(message, n) >= 0) {
        throw std::runtime_error("Message too large for modulus");
    }
    return modExpNormal(message, e, n);
}

BigNumPtr RsaAlgo::encryptSquareMultiply(const BIGNUM *message, const BIGNUM *e, const BIGNUM *n) {
    if (BN_cmp(message, n) >= 0) {
        throw std::runtime_error("Message too large for modulus");
    }
    return modExpSquareAndMultiply(message, e, n);
}

BigNumPtr RsaAlgo::decryptNormal(const BIGNUM *cipher, const BIGNUM *d, const BIGNUM *n) {
    return modExpNormal(cipher, d, n);
}

BigNumPtr RsaAlgo::decryptSquareMultiply(const BIGNUM *cipher, const BIGNUM *d, const BIGNUM *n) {
    return modExpSquareAndMultiply(cipher, d, n);
}

RsaKeyPair RsaAlgo::generateKeyPair(std::size_t key_bits) {
    if (key_bits % 128 != 0 || key_bits < MIN_KEY_BITS || key_bits > MAX_KEY_BITS) {
        throw std::runtime_error("Unsupported key size; choose 128, 256, 512, 1024, 2048, or 4096 bits");
    }

    std::size_t primeBits = key_bits / 2;

    BigNumPtr p = generatePrime(primeBits, nullptr);
    BigNumPtr q = generatePrime(primeBits, p.get());

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BigNumPtr n = makeInitialized();
    BigNumPtr phi = makeInitialized();
    BigNumPtr p_minus = clone(p.get());
    BigNumPtr q_minus = clone(q.get());

    BN_mul(n.get(), p.get(), q.get(), ctx);

    BN_sub_word(p_minus.get(), 1);
    BN_sub_word(q_minus.get(), 1);
    BN_mul(phi.get(), p_minus.get(), q_minus.get(), ctx);

    BigNumPtr e = makeInitialized();
    BN_set_word(e.get(), 65537);
    BigNumPtr one = makeInitialized();
    BN_one(one.get());

    BigNumPtr g = gcd(e.get(), phi.get());
    if (BN_cmp(g.get(), one.get()) != 0) {
        BN_set_word(e.get(), 3);
        while (BN_cmp(g.get(), one.get()) != 0) {
            BN_add_word(e.get(), 2);
            g = gcd(e.get(), phi.get());
        }
    }

    BigNumPtr d = modInverse(e.get(), phi.get());

    BN_CTX_free(ctx);

    RsaKeyPair pair;
    pair.n = std::move(n);
    pair.e = std::move(e);
    pair.d = std::move(d);
    pair.p = std::move(p);
    pair.q = std::move(q);
    pair.phi = std::move(phi);
    pair.key_bits = key_bits;

    return pair;
}

BigNumPtr RsaAlgo::messageToInt(const std::string &message) {
    BigNumPtr value = makeInitialized();
    BN_bin2bn(reinterpret_cast<const unsigned char *>(message.data()), static_cast<int>(message.size()), value.get());
    return value;
}

std::string RsaAlgo::intToMessage(const BIGNUM *value) {
    int size = BN_num_bytes(value);
    std::string output(size, '\0');
    BN_bn2bin(value, reinterpret_cast<unsigned char *>(&output[0]));
    return output;
}

} // namespace rsa
