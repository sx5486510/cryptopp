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
#include <nan.h>

#include <cryptopp/aes.h>

#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

#include "assert.h"

#include <cryptopp/base64.h>
#include <cryptopp/secblock.h>

using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::CFB_Mode;
using CryptoPP::AES;
using CryptoPP::Exception;

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

void CBC_AESEncryptStr(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
	Local<Object> input = info[0]->ToObject();
	Local<Object> input2 = info[1]->ToObject();
	Local<Object> input3 = info[2]->ToObject();

	if (!Buffer::HasInstance(input))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	if (!Buffer::HasInstance(input2))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	std::string sKey = std::string(Buffer::Data(input), Buffer::Length(input));
	std::string plain = std::string(Buffer::Data(input2), Buffer::Length(input2));
	std::string sIV = std::string(Buffer::Data(input3), Buffer::Length(input3));
	string cipher, encoded;

	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) :
		memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv  
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	try
	{
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);
		StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::ZEROS_PADDING)); // StringSource

	// Pretty print
		encoded.clear();
		StringSource(cipher, true, new Base64Encoder(new StringSink(encoded))); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cout << e.what() << endl;
	}

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)encoded.data(), encoded.size()).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void CBC_AESDecryptStr(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	if (info.Length() < 1)
		return THROW_ERROR_EXCEPTION("You must provide one argument.");

	Local<Object> input = info[0]->ToObject();
	Local<Object> input2 = info[1]->ToObject();
	Local<Object> input3 = info[2]->ToObject();

	if (!Buffer::HasInstance(input))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	if (!Buffer::HasInstance(input2))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	if (!Buffer::HasInstance(input3))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	std::string sKey = std::string(Buffer::Data(input), Buffer::Length(input));
	std::string cipherText = std::string(Buffer::Data(input2), Buffer::Length(input2));
	std::string sIV = std::string(Buffer::Data(input3), Buffer::Length(input3));
	std::string recovered;

	cout << sKey.c_str() << endl;
	cout << cipherText.c_str() << endl;
	cout << sIV.c_str() << endl;

	/*SecByteBlock*/ byte key[AES::MAX_KEYLENGTH];
	memset((void *)&key[0], 0x30, AES::MAX_KEYLENGTH);
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) :
		memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv  
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		// 	padding as required.

		StringSource s(cipherText/*cipher*/, true, new Base64Decoder(new StreamTransformationFilter(d, (new StringSink(recovered)), StreamTransformationFilter::ZEROS_PADDING))); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cout << e.what() << endl;
	}

	int len = strlen(recovered.c_str());
	if (len > 0)
	{
		recovered.resize(len);
	}

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)recovered.data(), recovered.length()).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

NAN_MODULE_INIT(init) {
	Nan::Set(target, Nan::New("ECB_AESDecryptStr").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(ECB_AESDecryptStr)).ToLocalChecked());
	Nan::Set(target, Nan::New("ECB_AESEncryptStr").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(ECB_AESEncryptStr)).ToLocalChecked());
	Nan::Set(target, Nan::New("CBC_AESEncryptStr").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(CBC_AESEncryptStr)).ToLocalChecked());
	Nan::Set(target, Nan::New("CBC_AESDecryptStr").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(CBC_AESDecryptStr)).ToLocalChecked());
}

NODE_MODULE(ECB_AESDecryptStr, init)