#include <iostream>
#include <iomanip>
#include <filesystem>
#include "server.h"
#include "cryptopp/randpool.h"


using namespace affix_returner;
namespace fs = std::filesystem;

const string PRIVATE_KEY_PATH = "private.bin";
const string PUBLIC_KEY_PATH = "public.bin";

int main(int argc, char* argv[]) {

    io_service l_service;
    udp::socket l_socket(l_service);
    
    rsa_key_pair kp;

    if (fs::exists(PRIVATE_KEY_PATH) && fs::exists(PUBLIC_KEY_PATH)) {
        rsa_import(kp.private_key, PRIVATE_KEY_PATH);
        rsa_import(kp.public_key, PUBLIC_KEY_PATH);
    }
    else {
        kp = rsa_generate_key_pair(4096);
        rsa_export(kp.private_key, PRIVATE_KEY_PATH);
        rsa_export(kp.public_key, PUBLIC_KEY_PATH);
    }

    server server_main(8090, kp.private_key, 5);
    
    while (true) {
        server_main.clean_connections();
        server_main.process_connections();
    }

    return 0;
}