#include <iostream>
#include "logic.h"

const char *PUBLIC_KEY_PATH = "./project/data/public-key.pem";
const char *PRIVATE_KEY_PATH = "./project/data/private-key.pem";

int main() {
    HW2::Trinket trinket(PRIVATE_KEY_PATH);
    HW2::Car car(PUBLIC_KEY_PATH);
    try {
        auto publicMessage = trinket.generateChallenge();  // The trinket begins handshake
        std::cout << "Trinket => Car: " << publicMessage << std::endl;
        publicMessage = car.processChallenge(publicMessage);  /* Part of the car handshake - a random
                                                               * value is generated for the signature */
        std::cout << "Trinket <= Car: " << publicMessage << std::endl;
        publicMessage = trinket.processChallenge(publicMessage);  // The trinket signs the challenge value
        std::cout << "Trinket => Car: " << publicMessage << std::endl;
        auto isDoorOpen = car.verifyChallengeSign(publicMessage);  // The car checks that the signature is correct
        std::cout << "Car: " << (isDoorOpen ? "doors open" : "doors remain closed") << std::endl;

    } catch (std::runtime_error &error) {
        std::cout << error.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << "some error.." << std::endl;
        return 1;
    }
    return 0;
}
