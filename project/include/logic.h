#ifndef HW2_LOGIC_H
#define HW2_LOGIC_H

#include <string>
#include <vector>
#include <memory>

namespace HW2 {
    class Trinket {
    public:
        /**
         * Construct trinket
         * @param trinketPrivateKey - path to trinket private key file
         * @param carPublicKey - path to car public key file
         */
        Trinket(const char *trinketPrivateKey, const char *carPublicKey);

        /**
         * Generates a random for testing the car and start the door opening process
         * @return random string
         */
        std::string generateChallenge();

        /**
         * Trinket check signature of the previously sent challenge and 
         * makes a signature for the received challenge value
         * @return only the signature
         */
        std::string processChallenge(const std::string &challengeValue);

    private:
        bool _isWaitChallenge;
        std::shared_ptr<EVP_PKEY> _trinketPrivateKey;
        std::shared_ptr<EVP_PKEY> _carPublicKey;
        std::vector<unsigned char> _challengeValue;
    };


    class Car {
    public:
        /**
         * Construct car
         * @param carPrivateKey
         * @param trinketPublicKey
         */
        Car(const char *carPrivateKey, const char *trinketPublicKey);

        /**
         * The car signs accepted challenge then generate a random value that the trinket must sign
         * @return a random value for the trinket challenge
         */
        std::string processChallenge(const std::string &challenge);

        /**
         * Checking that the challenge value signature made by a true trinket
         * @return is the challenge successful
         */
        bool verifyChallengeSign(const std::string &trinketResponse);

    private:
        std::shared_ptr<EVP_PKEY> _carPrivateKey;
        std::shared_ptr<EVP_PKEY> _trinketPublicKey;
        std::vector<unsigned char> _challengeValue;
    };

}  // namespace HW2

#endif  // HW2_LOGIC_H
