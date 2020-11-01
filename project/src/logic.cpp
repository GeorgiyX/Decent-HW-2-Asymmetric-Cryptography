#include <stdexcept>
#include <cstring>
#include <openssl/rand.h>
#include <iostream>
#include "logic.h"
#include "crypto.h"


namespace HW2 {
    const char *TRINKET_HELLO = "Hi car, open the door";
    size_t CHALLENGE_VALUE_SIZE = 32;

    Trinket::Trinket(const char *trinketPrivateKey, const char *carPublicKey) : _isWaitChallenge(false),
                                                                                _trinketPrivateKey(readPrivateKey(
                                                                                        trinketPrivateKey)),
                                                                                _carPublicKey(
                                                                                        readPublicKey(carPublicKey)),
                                                                                _challengeValue(CHALLENGE_VALUE_SIZE) {
        std::cout << "The trinket load its private key: " << std::string(trinketPrivateKey) << std::endl;
        std::cout << "The trinket load car public key: " << std::string(carPublicKey) << std::endl;
    }

    std::string Trinket::generateChallenge() {
        _isWaitChallenge = true;
        setRandBytes(_challengeValue);
        return std::string(reinterpret_cast<const char *>(_challengeValue.data()), _challengeValue.size());
    }

    std::string Trinket::processChallenge(const std::string &challengeValue) {
        /* if the hacker sent generate challenge to the car (and not the trinket),
         * the trinket should not respond */
        if (!_isWaitChallenge) {
            throw std::runtime_error("The challenge was not expected");
        }

        /* The first 20 characters are trinket challenge data,
         * the remaining characters are the car challenge signature */
        auto trinketChallenge = challengeValue.substr(0, CHALLENGE_VALUE_SIZE);
        auto carChallengeSignature = challengeValue.substr(CHALLENGE_VALUE_SIZE);
        if (!verifyMessage(_challengeValue,
                           reinterpret_cast<const unsigned char *>(carChallengeSignature.c_str()),
                           carChallengeSignature.size(),
                           _carPublicKey.get())) {
            throw std::runtime_error("The car challenge is invalid");
        }


    /* copy trinket challenge to vector */
    std::vector<unsigned char> challengeData(challengeValue.length(), '\0');
    memcpy(challengeData.data(), challengeValue.data(), challengeData.size());

    unsigned char *signature = nullptr;
    size_t signatureLen = 0;
    signMessage(challengeData, &signature, &signatureLen, _trinketPrivateKey.get());
    std::string signatureString(reinterpret_cast<const char *>(signature), signatureLen);

    OPENSSL_free(signature);
    return signatureString;
}

Car::Car(const char *pathToPublicKey) :
        _publicKey(pathToPublicKey),
        _challengeValue(CHALLENGE_VALUE_SIZE, '\0') {
    std::cout << "The car uses a public key: " + std::string(_publicKey) << std::endl;
}

std::string Car::processChallenge(const std::string &trinketChallenge) {
    if (trinketChallenge != TRINKET_HELLO) {
        throw std::runtime_error("wrong trinket hello");
    }

    setRandBytes(_challengeValue));

    return std::string(reinterpret_cast<const char *>(_challengeValue.data()), _challengeValue.size());
}

bool Car::verifyChallengeSign(const std::string &challengeResponse) {
    auto *publicKey = readPublicKey(_publicKey);
    auto isSignatureValid = verifyMessage(_challengeValue,
                                          reinterpret_cast<const unsigned char *>(challengeResponse.data()),
                                          challengeResponse.size(), publicKey);
    EVP_PKEY_free(publicKey);  // TODO: memory leak if a verifyMessage throws an exception
    return isSignatureValid;
}

}  // namespace HW2