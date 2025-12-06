/**
 * @file rsa.hpp
 * @brief Defines the public interface for a simple RSA encryption and signature library.
 */

#ifndef RSA_HPP
#define RSA_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

/**
 * @brief A simple implementation of the RSA public-key cryptosystem.
 *
 * This namespace contains classes for generating RSA keys and for encrypting,
 * decrypting, signing, and verifying messages.
 */
namespace rsa {

/**
 * @brief Represents an RSA public key.
 */
struct PublicKey {
    uint64_t modulus;  ///< The modulus (n) for the RSA key pair.
    uint64_t exponent; ///< The public exponent (e).
};

/**
 * @brief Represents an RSA private key.
 */
struct PrivateKey {
    uint64_t modulus;  ///< The modulus (n) for the RSA key pair.
    uint64_t exponent; ///< The private exponent (d).
};

/**
 * @brief A utility class for generating RSA key pairs.
 *
 * All methods are static, so no instance of this class is needed.
 */
class KeyGenerator {
public:
    /**
     * @brief Creates a public key from two prime numbers and a public exponent.
     * @param prime1 The first prime number (p).
     * @param prime2 The second prime number (q).
     * @param publicExponent The public exponent (e).
     * @return The generated PublicKey.
     * @throw std::invalid_argument if the public exponent is not coprime with the totient.
     */
    static PublicKey makePublicKey(uint64_t prime1, uint64_t prime2, uint64_t publicExponent);

    /**
     * @brief Creates a private key from two prime numbers and a public exponent.
     * @param prime1 The first prime number (p).
     * @param prime2 The second prime number (q).
     * @param publicExponent The public exponent (e), used to derive the private exponent.
     * @return The generated PrivateKey.
     * @throw std::invalid_argument if the public exponent is not coprime with the totient.
     */
    static PrivateKey makePrivateKey(uint64_t prime1, uint64_t prime2, uint64_t publicExponent);

private:
    /**
     * @brief Computes Euler's totient function for n = p * q.
     * @param prime1 The first prime number (p).
     * @param prime2 The second prime number (q).
     * @return The result of (p-1) * (q-1).
     */
    static uint64_t computeTotient(uint64_t prime1, uint64_t prime2);

    /**
     * @brief Computes the modular multiplicative inverse of a value.
     * Uses the Extended Euclidean Algorithm.
     * @param value The value to find the inverse of.
     * @param modulus The modulus.
     * @return The modular inverse.
     * @throw std::invalid_argument if the value is not invertible.
     */
    static uint64_t modularInverse(uint64_t value, uint64_t modulus);

    /**
     * @brief Computes the greatest common divisor (GCD) of two numbers.
     * @param a The first number.
     * @param b The second number.
     * @return The GCD of a and b.
     */
    static uint64_t gcd(uint64_t a, uint64_t b);
};

/**
 * @brief A utility class for RSA encryption, decryption, signing, and verification.
 *
 * All methods are static. This implementation processes messages character by character.
 */
class Cipher {
public:
    /**
     * @brief Encrypts a message using a public key.
     * @param message The plaintext string to encrypt.
     * @param key The public key to use for encryption.
     * @return A vector of 64-bit integers representing the encrypted blocks.
     * @throw std::invalid_argument if the key modulus is too small.
     */
    static std::vector<uint64_t> encrypt(const std::string &message, const PublicKey &key);

    /**
     * @brief Decrypts a ciphertext using a private key.
     * @param ciphertext A vector of encrypted blocks.
     * @param key The private key to use for decryption.
     * @return The decrypted plaintext string.
     * @throw std::invalid_argument if the key modulus is too small.
     * @throw std::runtime_error if a decrypted value is not a valid ASCII character.
     */
    static std::string decrypt(const std::vector<uint64_t> &ciphertext, const PrivateKey &key);

    /**
     * @brief Signs a message using a private key.
     * @param message The message to sign.
     * @param key The private key to use for signing.
     * @return A vector of 64-bit integers representing the signature.
     * @throw std::invalid_argument if the key modulus is too small.
     */
    static std::vector<uint64_t> sign(const std::string &message, const PrivateKey &key);

    /**
     * @brief Verifies a signature against a message using a public key.
     * @param message The original message.
     * @param signature The signature to verify.
     * @param key The public key corresponding to the private key used for signing.
     * @return True if the signature is valid for the message, false otherwise.
     */
    static bool verify(const std::string &message, const std::vector<uint64_t> &signature, const PublicKey &key);

private:
    /**
     * @brief Performs modular exponentiation (base^exponent % modulus).
     * Uses the right-to-left binary method for efficiency.
     * @param base The base of the operation.
     * @param exponent The exponent.
     * @param modulus The modulus.
     * @return The result of the operation.
     */
    static uint64_t modularExponentiation(uint64_t base, uint64_t exponent, uint64_t modulus);

    /**
     * @brief Validates that the RSA modulus is large enough for this implementation.
     * @param modulus The modulus to check.
     * @throw std::invalid_argument if the modulus is not greater than the ASCII limit (255).
     */
    static void validateKeyModulus(uint64_t modulus);
};

} // namespace rsa

#endif // RSA_HPP
