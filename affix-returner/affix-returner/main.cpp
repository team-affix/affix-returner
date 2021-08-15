#include <iostream>
#include <iomanip>

#include <net-common/net_common.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/pssr.h>
#include <string>
using namespace CryptoPP;
using std::string;

// Returns the cipher integer
Integer rsa_example() {

    AutoSeededRandomPool random;
    AutoSeededRandomPool random2;

    RSA::PrivateKey priKey;
    
    priKey.GenerateRandomWithKeySize(random, 1024);
    
    RSA::PublicKey pubKey(priKey);

    bool b2 = priKey.Validate(random, 3);

    vector<byte> vec;
    VectorSink vectorSink(vec);
    priKey.Save(vectorSink);

    RSA::PrivateKey newPrivateKey;
    VectorSource vectorSource(vec, true);
    newPrivateKey.Load(vectorSource);

    
    string input = "secret";

    Integer input_integer((const byte*)input.data(), input.size());
    std::cout << "input:     " << std::hex << input_integer << std::endl;

    RSAES<OAEP<SHA256>>::Encryptor encryptor(pubKey);

    SecByteBlock cipher(encryptor.CiphertextLength(input.size()));
    
    encryptor.Encrypt(random, (const byte*)input.data(), input.size(), cipher);

    Integer cipher_integer((const byte*)cipher.data(), cipher.size());
    std::cout << "cipher: " << std::hex << cipher_integer << std::endl;

    RSAES<OAEP<SHA256>>::Decryptor decryptor(newPrivateKey);

    SecByteBlock recovered(decryptor.MaxPlaintextLength(cipher.size()));

    DecodingResult decoding_result = decryptor.Decrypt(random2, cipher, cipher.size(), recovered);

    recovered.resize(decoding_result.messageLength);

    Integer recovered_integer((const byte*)recovered.data(), recovered.size());
    std::cout << "recovered: " << std::hex << recovered_integer << std::endl;

    assert(input_integer == recovered_integer);

    //std::cin.get();
    return cipher_integer;
}

struct rsa_key_pair {
    RSA::PrivateKey private_key;
    RSA::PublicKey public_key;
};

rsa_key_pair generate_key_pair(uint32_t a_key_size) {
    AutoSeededRandomPool random;
    RSA::PrivateKey priKey;
    priKey.GenerateRandomWithKeySize(random, a_key_size);
    RSA::PublicKey pubKey(priKey);
    return { priKey, pubKey };
}

vector<byte> rsa_encrypt(const vector<byte>& a_input, RSA::PublicKey a_public_key) {
    AutoSeededRandomPool random;
    RSAES<OAEP<SHA256>>::Encryptor encryptor(a_public_key);
    SecByteBlock cipher(encryptor.CiphertextLength(a_input.size()));
    encryptor.Encrypt(random, a_input.data(), a_input.size(), cipher);
    vector<byte> result(cipher.size());
    memcpy(result.data(), cipher.data(), cipher.size());
    return result;
}

vector<byte> rsa_decrypt(const vector<byte>& a_input, RSA::PrivateKey a_private_key) {
    AutoSeededRandomPool random;
    RSAES<OAEP<SHA256>>::Decryptor decryptor(a_private_key);
    SecByteBlock plain(decryptor.MaxPlaintextLength(a_input.size()));
    DecodingResult decoding_result = decryptor.Decrypt(random, a_input.data(), a_input.size(), plain);
    plain.resize(decoding_result.messageLength);
    vector<byte> result(plain.size());
    memcpy(result.data(), plain.data(), plain.size());
    return result;
}

template<typename T>
vector<T> sub_vector(const vector<T>& a_vec, size_t a_start, size_t a_len) {
    vector<T> result(a_len);
    for (int i = 0; i < a_len; i++)
        result[i] = a_vec[a_start + i];
    return result;
}

vector<vector<byte>> rsa_encrypt_in_chunks(const vector<byte>& a_input, RSA::PublicKey a_public_key) {
    RSAES<OAEP<SHA256>>::Encryptor encryptor(a_public_key);
    vector<vector<byte>> result;
    for (int i = 0; i < a_input.size(); i += encryptor.FixedMaxPlaintextLength()) {
        size_t bytes_remaining = a_input.size() - i;
        vector<byte> chunk = sub_vector(a_input, i, std::min(encryptor.FixedMaxPlaintextLength(), bytes_remaining));
        result.push_back(rsa_encrypt(chunk, a_public_key));
    }
    return result;
}

vector<byte> rsa_decrypt_in_chunks(const vector<vector<byte>>& a_input, RSA::PrivateKey a_private_key) {
    vector<byte> result;
    for (int i = 0; i < a_input.size(); i++) {
        const vector<byte>& chunk = a_input[i];
        vector<byte> decrypted = rsa_decrypt(chunk, a_private_key);
        result.insert(result.end(), decrypted.begin(), decrypted.end());
    }
    return result;
}

vector<byte> rsa_sign(const vector<byte>& a_input, RSA::PrivateKey a_private_key) {
    AutoSeededRandomPool random;
    RSASS<PSS, SHA256>::Signer signer(a_private_key);
    SecByteBlock signature(signer.MaxSignatureLength());
    size_t length = signer.SignMessage(random, a_input.data(), a_input.size(), signature);
    signature.resize(length);
    vector<byte> result(signature.size());
    memcpy(result.data(), signature.data(), signature.size());
    return result;
}

bool rsa_verify(const vector<byte>& a_input, const vector<byte>& a_signature, RSA::PublicKey a_public_key) {
    AutoSeededRandomPool random;
    RSASS<PSS, SHA256>::Verifier verifier(a_public_key);
    return verifier.VerifyMessage(a_input.data(), a_input.size(), a_signature.data(), a_signature.size());
}

int main(int argc, char* argv[]) {



    return 0;
}