#ifndef HW2_UTILS_H
#define HW2_UTILS_H

#include <string>

namespace HW2 {
    class Trinket {
    public:
        /**
         * @param pathToPrivateKey - path to trinket .priv file
         */
        Trinket(std::string pathToPrivateKey);

        /**
         * Make "open door" request
         * @return "open door" string
         */
        std::string trinketGenerateHandShake();

        /**
         * Trinket makes a signature for the received challenge value
         * @return only the signature
         */
        std::string trinketProcessChallenge(std::string);


    private:
        /**
         * Make rsa sign
         * @return coded input
         */
        std::string trinketMakeSign(int);

        std::string _privateKey;
    };


    class Car {
    public:
        /**
         * @param pathToPublicKey - path to trinket .pub file
         */
        Car(std::string pathToPublicKey);

        /**
         * The car starts the challenge: generate a random value that the trinket must sign
         * @return a random value for the trinket challenge
         */
        int carProcessHandshake(std::string);

        /**
         * Checking that the challenge value signature made by a true trinket
         * @return is the challenge successful
         */
        bool carVerifySign(std::string);

    private:
        std::string _publicKey;
        int _challengeValue;
    };
}  // namespace HW2

#endif  // HW2_UTILS_H
