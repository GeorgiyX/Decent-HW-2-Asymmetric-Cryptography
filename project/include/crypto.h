#ifndef HW2_CRYPTO_H
#define HW2_CRYPTO_H

#include <string>
#include <vector>
#include <openssl/pem.h>

namespace HW2 {
    /**
     * Reading the key file into a special structure
     * @param keyPath - path to public key file
     * @return shared pointer to EVP_PKEY.
     */
    std::shared_ptr<EVP_PKEY> readPublicKey(const char *keyPath);
    /**
     * Reading the key file into a special structure
     * @param keyPath - path to public key file
     * @return shared pointer to EVP_PKEY.
     */
    std::shared_ptr<EVP_PKEY> readPrivateKey(const char *keyPath);
    /**
     * Generates a signature for a message.
     * @todo return string, remove signature & signatureLen
     * @param message
     * @param signature Remember to use OPENSSL_free.
     * @param signatureLen
     * @param privateRSA
     */
    void signMessage(std::string message, unsigned char **signature, size_t *signatureLen, EVP_PKEY *privateRSA);
    /**
     * Verify the message signature.
     * @todo EVP_PKEY - shared ptr
     * @param message
     * @param signature
     * @param publicRSA
     * @return whether the signature is correct
     */
    bool verifyMessage(std::vector<unsigned char> &message, std::string signature, EVP_PKEY *publicRSA);
    /**
     * Wrapper around RAND_bytes
     */
    void setRandBytes(std::vector<unsigned char> &buffer);

}  // namespace HW2

#endif  // HW2_CRYPTO_H
