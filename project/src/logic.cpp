#include <stdexcept>
#include <cstring>
#include <openssl/rand.h>
#include <iostream>
#include "logic.h"
#include "crypto.h"


namespace HW2 {
    size_t CHALLENGE_VALUE_SIZE = 32;

    Trinket::Trinket(const char *trinketPrivateKey, const char *carPublicKey) : _isWaitChallenge(false),
                                                                                _trinketPrivateKey(readPrivateKey(
                                                                                        trinketPrivateKey)),
                                                                                _carPublicKey(
                                                                                        readPublicKey(carPublicKey)),
                                                                                _challengeValue(CHALLENGE_VALUE_SIZE, '\0') {
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

        /* The first CHALLENGE_VALUE_SIZE characters are trinket challenge data,
         * the remaining characters are the car challenge signature */
        auto trinketChallenge = challengeValue.substr(0, CHALLENGE_VALUE_SIZE);
        auto carChallengeSignature = challengeValue.substr(CHALLENGE_VALUE_SIZE);
        if (!verifyMessage(_challengeValue,
                           carChallengeSignature,
                           _carPublicKey.get())) {
            throw std::runtime_error("The car challenge is invalid");
        }

        unsigned char *signature = nullptr;
        size_t signatureLen = 0;
        signMessage(trinketChallenge, &signature, &signatureLen, _trinketPrivateKey.get());
        std::string signatureString(reinterpret_cast<const char *>(signature), signatureLen);
        OPENSSL_free(signature);

        return signatureString;
    }

    Car::Car(const char *carPrivateKey, const char *trinketPublicKey) :
    _carPrivateKey(readPrivateKey(carPrivateKey)), _trinketPublicKey(readPublicKey(trinketPublicKey)),
    _challengeValue(CHALLENGE_VALUE_SIZE, '\0') {
        std::cout << "The car load its private key: " << std::string(carPrivateKey) << std::endl;
        std::cout << "The car load trinket public key: " << std::string(trinketPublicKey) << std::endl;
    }

    std::string Car::processChallenge(const std::string &challengeValue) {

        unsigned char *signature = nullptr;
        size_t signatureLen = 0;
        signMessage(challengeValue, &signature, &signatureLen, _carPrivateKey.get());
        std::string signatureString(reinterpret_cast<const char *>(signature), signatureLen);
        OPENSSL_free(signature);

        setRandBytes(_challengeValue);
        auto carResponse = std::string(reinterpret_cast<const char *>(_challengeValue.data()), _challengeValue.size()) +
                           std::string(reinterpret_cast<const char *>(_challengeValue.data()), _challengeValue.size());

        return carResponse;
    }

    bool Car::verifyChallengeSign(const std::string &trinketResponse) {
        return verifyMessage(_challengeValue, trinketResponse, _trinketPublicKey.get());
    }

}  // namespace HW2