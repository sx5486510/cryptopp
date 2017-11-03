//Std imports
#include <string>
#include <iostream>
#include <exception>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <utility>

//Node and class headers import
#include <node.h>

#include <cryptopp/aes.h>

#include <cryptopp/modes.h>
#include <cryptopp/hex.h>

using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::CFB_Mode;
using CryptoPP::AES;

using namespace v8;
using namespace std;
using namespace CryptoPP;
using namespace node;

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void ECB_AESDecryptStr(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	if (info.Length() < 1)
		return THROW_ERROR_EXCEPTION("You must provide one argument.");

	Local<Object> input = info[0]->ToObject();
	Local<Object> input2 = info[1]->ToObject();

	if (!Buffer::HasInstance(input))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	if (!Buffer::HasInstance(input2))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	std::string sKey = std::string(Buffer::Data(input), Buffer::Length(input));
	std::string cipherText = std::string(Buffer::Data(input2), Buffer::Length(input2));

	std::string outstr;
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	if (sKey.size() <= AES::MAX_KEYLENGTH)
		memcpy(key, sKey.c_str(), sKey.size());
	else
		memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	ECB_Mode<AES >::Decryption ecbDecryption((byte *)key, AES::MAX_KEYLENGTH);

	HexDecoder decryptor(new StreamTransformationFilter(ecbDecryption, new StringSink(outstr)));
	decryptor.Put((byte *)cipherText.c_str(), cipherText.length());
	decryptor.MessageEnd();

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)outstr.data(), outstr.size()).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void ECB_AESEncryptStr(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
	Local<Object> input = info[0]->ToObject();
	Local<Object> input2 = info[1]->ToObject();

	if (!Buffer::HasInstance(input))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	if (!Buffer::HasInstance(input2))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	std::string sKey = std::string(Buffer::Data(input), Buffer::Length(input));
	std::string plainText = std::string(Buffer::Data(input2), Buffer::Length(input2));

	std::string outstr;
	//Ìîkey  
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	if (sKey.size() <= AES::MAX_KEYLENGTH)
		memcpy(key, sKey.c_str(), sKey.size());
	else
		memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	AES::Encryption aesEncryption((byte *)key, AES::MAX_KEYLENGTH);

	ECB_Mode_ExternalCipher::Encryption ecbEncryption(aesEncryption);
	StreamTransformationFilter ecbEncryptor(ecbEncryption, new HexEncoder(new StringSink(outstr)));
	ecbEncryptor.Put((byte *)plainText.c_str(), plainText.length());
	ecbEncryptor.MessageEnd();

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)outstr.data(), outstr.size()).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

NAN_MODULE_INIT(init) {
	Nan::Set(target, Nan::New("ECB_AESDecryptStr").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(ECB_AESDecryptStr)).ToLocalChecked());
	Nan::Set(target, Nan::New("ECB_AESEncryptStr").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(ECB_AESEncryptStr)).ToLocalChecked());
}

NODE_MODULE(ECB_AESDecryptStr, init)
