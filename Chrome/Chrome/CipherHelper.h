#pragma once
#include <memory>
#include <string>
#include <assert.h>
#include <Windows.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/hmac.h>


#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define SCEE_NONCE_LENGTH 12

class SSLHelper{
public:

	// base function
	static std::string EncodeHex(std::string str, int len) {
		std::string res = "";
		char tmp[3] = {0};
		for (int i = 0; i < len; ++i) {
			sprintf(tmp, "%02x", (unsigned char)str.c_str()[i]);
			res += tmp;
		}
		return res;
	}

	static std::string convert_ASCII(std::string hex){
		std::string ascii = "";
		for (size_t i = 0; i < hex.length(); i += 2){
			std::string part = hex.substr(i, 2);
			char ch = stoul(part, nullptr, 16);
			ascii += ch;
		}
		return ascii;
	}

	// base64
	static std::string Base64Encode(const void* str, int len) {
		BIO* bmem = NULL;
		BIO* b64 = NULL;
		BUF_MEM* bptr = NULL;

		b64 = BIO_new(BIO_f_base64());
		if (!b64) {
			return "";
		}
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		bmem = BIO_new(BIO_s_mem());
		if (!bmem) {
			return "";
		}
		b64 = BIO_push(b64, bmem);
		BIO_write(b64, (const char*)str, len);
		BIO_flush(b64);
		BIO_get_mem_ptr(b64, &bptr);
		std::string res = "";
		std::unique_ptr<char[]>buffer(new char[bptr->length + 1]);
		memcpy(buffer.get(), bptr->data, bptr->length);
		BIO_free_all(b64);
		res = std::string(buffer.get(), bptr->length);
		return res;
	}
	
	static std::string Base64Encode(std::string str, int len) {
		return Base64Encode(str.c_str(), len);
	}

	static std::string Base64Decode(const void* base64, int& dwLen) {
		BIO* b64 = NULL;
		BIO* bmem = NULL;
		int len = dwLen;
		char* buffer = new char[len + 1];
		memset(buffer, 0, len);
		b64 = BIO_new(BIO_f_base64());
		if (!b64) {
			return "";
		}

		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

		bmem = BIO_new_mem_buf((const char*)base64, len);
		bmem = BIO_push(b64, bmem);
		dwLen = BIO_read(bmem, buffer, len);
		BIO_free_all(b64);
		std::string res = std::string(buffer, len);
		delete[] buffer;
		return res;
	}

	static std::string Base64Decode(std::string base64, int& dwLen) {
		dwLen = base64.size();
		return Base64Decode(base64.c_str(), dwLen);
	}

	// Hash function
	static std::string md5(const void* src, int len) {
		unsigned char res[MD5_DIGEST_LENGTH + 1] = { 0 };
		MD5((unsigned const char*)src, len, res);
		return std::string((char*)res, MD5_DIGEST_LENGTH);
	}

	static std::string md5(std::string src, int len) {
		return md5(src.c_str(), len);
	}

	static std::string sha1(const void *src, int len) {
		unsigned char res[SHA_DIGEST_LENGTH + 1] = {0};
		SHA1((unsigned const char*)src, len, res);
		return std::string((char*)res, SHA_DIGEST_LENGTH);
	}

	static std::string sha1(std::string src, int len) {
		return sha1(src.c_str(), len);
	}

	static std::string sha256(std::string src, int len) {
		unsigned char res[SHA256_DIGEST_LENGTH + 1] = {0};
		SHA256((unsigned char*)src.c_str(), len, res);
		return std::string((char*)res, SHA256_DIGEST_LENGTH);
	}

	static std::string sha384(std::string src, int len) {
		unsigned char res[SHA384_DIGEST_LENGTH + 1] = {0};
		SHA384((unsigned char*)src.c_str(), len, res);
		return std::string((char*)res, SHA384_DIGEST_LENGTH);
	}

	static std::string sha512(std::string src, int len) {
		unsigned char res[SHA512_DIGEST_LENGTH + 1] = {0};
		SHA512((unsigned char*)src.c_str(), len, res);
		return std::string((char*)res, SHA512_DIGEST_LENGTH); 
	}

	// DES-ECB
	static std::string DesECBEncrypt(std::string plain, int data_len, std::string key, int& szLen, int key_len = 8) {
		std::string cipher = "";
		DES_cblock keyEncrypt;
		memset(keyEncrypt, 0, sizeof(keyEncrypt));
		// padding
		if (key_len <= sizeof(keyEncrypt))
			memcpy(keyEncrypt, key.c_str(), key_len);
		else
			memcpy(keyEncrypt, key.c_str(), sizeof(keyEncrypt));
		// 
		DES_key_schedule keySchedule;
		DES_set_key_unchecked(&keyEncrypt, &keySchedule);
		// 
		const_DES_cblock input;
		DES_cblock output;
		std::string res = "";
		int block_number = data_len >> 3;
		szLen = block_number << 3;
		for (int i = 0; i < block_number; ++i) {
			memcpy(input, plain.c_str() + i * 8, 8);
			DES_ecb_encrypt(&input, &output, &keySchedule, DES_ENCRYPT);
			res += std::string((char*)output, 8);
		}

		if (data_len % 8 != 0) {
			memset(input, 8 - data_len % 8, 8);
			int offset = block_number << 3;
			memcpy(input, plain.c_str() + offset, data_len % 8);
			DES_ecb_encrypt(&input, &output, &keySchedule, DES_ENCRYPT);
			res += std::string((char*)output, 8);
			szLen += 8;
		}
		return res;
	}

	static std::string DesECBDecrypt(std::string cipher, int data_len, std::string key, int& szLen, int key_len = 8) {
		DES_cblock keyEncrypt;
		memset(keyEncrypt, 0, sizeof(DES_cblock));
		if(key_len<= sizeof(DES_cblock))
			memcpy(keyEncrypt, key.c_str(), key_len);
		else
			memcpy(keyEncrypt, key.c_str(), sizeof(DES_cblock));
		// 
		DES_key_schedule keySchedule;
		DES_set_key_unchecked(&keyEncrypt, &keySchedule);

		// 
		const_DES_cblock input;
		DES_cblock output;
		std::string res = "";
		int block_number = data_len >> 3;
		szLen = block_number << 3;
		for (int i = 0; i < block_number; ++i) {
			memcpy(input, cipher.c_str() + i * 8, 8);
			DES_ecb_encrypt(&input,&output,&keySchedule, DES_DECRYPT);
			res += std::string((char*)output, 8);
		}

		if (data_len % 8 != 0) {
			memset(input, 8 - data_len % 8, 8);
			int offset = block_number << 3;
			memcpy(input,cipher.c_str() + offset, data_len % 8);
			DES_ecb_encrypt(&input, &output, &keySchedule, DES_DECRYPT);
			res += std::string((char*)output, 8);
			szLen += 8;
		}
		return res;
	}

	// AES-CBC
	static std::string AesCBCEncrypt(const void *plain, int data_len, const void *key, int& outLen, int key_len, const void *iv = "") {
		AES_KEY aes_key;
		if (AES_set_encrypt_key((unsigned char*)key, key_len << 3, &aes_key) < 0) {
			return "";
		}

		int padding = 0;
		// ZeroPadding
		if (data_len % AES_BLOCK_SIZE > 0) {
			padding = AES_BLOCK_SIZE - data_len % AES_BLOCK_SIZE;
		}

		int pad_num = padding;
		outLen = data_len;
		outLen += padding;

		std::string data = std::string((const char *)plain, data_len);
		while (padding) {
			data += (char)pad_num;
			padding--;
		}

		// 
		unsigned char output[AES_BLOCK_SIZE];
		unsigned char input[AES_BLOCK_SIZE];
		std::string res = "";
		int block_num = outLen >> 4;
		for (int i = 0; i < block_num; ++i) {
			memcpy(input, data.c_str() + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
			memset(output, 0, AES_BLOCK_SIZE);
			AES_cbc_encrypt((const unsigned char*)input, output, AES_BLOCK_SIZE, &aes_key, (unsigned char*)iv, AES_ENCRYPT);
			res += std::string((const char*)output, AES_BLOCK_SIZE);
		}
		return res;
	}

	static std::string AesCBCDecrypt(const void *src, int data_len, const void *key, int key_len, const void *iv) {
		AES_KEY aes_key;
		if (AES_set_decrypt_key((const unsigned char*)key, key_len << 3, &aes_key) < 0) {
			return "";
		}
		// 
		unsigned char output[AES_BLOCK_SIZE];
		unsigned char input[AES_BLOCK_SIZE];
		std::string res = "";
		int block_num = data_len >> 4;
		for (int i = 0; i < block_num; ++i) {
			memset(output, 0, AES_BLOCK_SIZE);
			memcpy(input, (char *)src + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
			AES_cbc_encrypt((const unsigned char*)input, output, AES_BLOCK_SIZE, &aes_key, (unsigned char*)iv, AES_DECRYPT);
			res += std::string((char*)output, AES_BLOCK_SIZE);
		}

		return res;
	}
	// AES-CBC(overload)
	static std::string AesCBCEncrypt(std::string plain, int data_len, std::string key, int& szLen, int key_len, std::string iv = "") {
		return AesCBCEncrypt(plain.c_str(), data_len, key.c_str(), szLen, key_len, iv.c_str());
	}

	static std::string AesCBCDecrypt(std::string src,int data_len, std::string key, int key_len, std::string iv = ""){
		return AesCBCDecrypt(src.c_str(), data_len, key.c_str(), key_len, iv.c_str());
	}
	
	// AES-GCM-256 ???
	static std::string AesGCMDecrypt(uint8_t* ciphertext_and_nonce, size_t ciphertext_and_nonce_length, const uint8_t* key, int key_length) {
		/*
		* AES-GCM-256
		* code may not always right
		* steal from following links
		* Also See
		* https://codereview.stackexchange.com/questions/194449/openssl-aes-gcm-convenience-wrapper-in-c
		*/
		size_t ciphertext_length = ciphertext_and_nonce_length - SCEE_NONCE_LENGTH;
		if (ciphertext_length <= 0) {
			return "";
		}
		uint8_t nonce[SCEE_NONCE_LENGTH] = { 0 };
		std::unique_ptr<uint8_t[]>ciphertext(new uint8_t[ciphertext_length]);
		memcpy(nonce, ciphertext_and_nonce, SCEE_NONCE_LENGTH);
		memcpy(ciphertext.get(), ciphertext_and_nonce + SCEE_NONCE_LENGTH, ciphertext_length);
		int status = 0;
		std::string plaintext = "";
		do {
			// Create the cipher context and initialize.
			EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
			if (ctx == NULL) {
				break;
			}
			status = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
			if (status == 0) {
				break;
			}

			status = EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
			if (status == 0) {
				break;
			}
			int readLength = 0;
			plaintext.resize(ciphertext_length);
			status = EVP_DecryptUpdate(ctx, (unsigned char *)plaintext.c_str(), &readLength, ciphertext.get(), ciphertext_length);
			if (status == 0) {
				break;
			}
			status = EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext.c_str() + readLength, &readLength);
			if (ciphertext_length > 16) {
				int count = 16;
				while (count > 0) {
					plaintext.pop_back();
					count--;
				}
			}
		} while (false);
		return plaintext;
	}

	// AES-ECB
	static std::string AesECBEncrypt(const void *plain, int data_len, const void *key, int& szLen, int key_len) {
		AES_KEY aes_key;
		if (AES_set_encrypt_key((unsigned char*)key, key_len << 3, &aes_key) < 0) {
			return "";
		}

		int padding = 0;
		// ZeroPadding
		if (data_len % AES_BLOCK_SIZE > 0) {
			padding = AES_BLOCK_SIZE - data_len % AES_BLOCK_SIZE;
		}

		int pad_num = padding;
		szLen = data_len;
		szLen += padding;

		std::string data = (char *)plain;
		while (padding) {
			data += (char)pad_num;
			padding--;
		}

		// 
		unsigned char output[AES_BLOCK_SIZE] = { 0 };
		unsigned char input[AES_BLOCK_SIZE] = { 0 };
		std::string res = "";
		int block_num = szLen >> 4;
		for (int i = 0; i < block_num; ++i) {
			memcpy(input, data.c_str() + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
			memset(output, 0, AES_BLOCK_SIZE);
			AES_ecb_encrypt((const unsigned char*)input, output, &aes_key, AES_ENCRYPT);
			res += std::string((const char*)output, AES_BLOCK_SIZE);
		}
		return res;
	}

	static std::string AesECBDecrypt(const void *src, int data_len, const void *key, int key_len) {
		AES_KEY aes_key;
		if (AES_set_decrypt_key((const unsigned char*)key, key_len << 3, &aes_key) < 0) {
			return "";
		}
		// 
		unsigned char output[AES_BLOCK_SIZE];
		unsigned char input[AES_BLOCK_SIZE];
		std::string res = "";
		int block_num = data_len >> 4;
		for (int i = 0; i < block_num; ++i) {
			memset(output, 0, AES_BLOCK_SIZE);
			memcpy(input, (char *)src + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
			AES_ecb_encrypt((const unsigned char*)input, output, &aes_key, AES_DECRYPT);
			res += std::string((char*)output, AES_BLOCK_SIZE);
		}
		return res;
	}
	// AES-ECB (overload)
	static std::string AesECBEncrypt(std::string plain, int data_len, std::string key, int& szLen, int key_len) {
		return AesECBEncrypt(plain.c_str(), data_len, key.c_str(), szLen, key_len);
	}

	static std::string AesECBDecrypt(std::string src,int data_len, std::string key, int key_len) {
		return AesECBDecrypt(src.c_str(), data_len, key.c_str(), key_len);
	}
	
	static std::string HMAC_SHA512(const void *key,int key_len, const void *msg, int msg_len) {
		HMAC_CTX *ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, key, key_len, EVP_sha512(), NULL);
		HMAC_Update(ctx, (unsigned char *)msg, msg_len);
		unsigned char output[SHA512_DIGEST_LENGTH] = { 0 };
		unsigned int output_length = 0;
		HMAC_Final(ctx, output, &output_length);
		HMAC_CTX_free(ctx);
		return std::string((char *)output, output_length);
	}

	static std::string PBKDF2_SHA512(const void *password, int pass_len, const void *salt, int salt_len, int iteration, int szLen) {
		BOOL status = FALSE;
		DWORD szHmac = SHA512_DIGEST_LENGTH;
		PBYTE asalt = NULL, obuf = NULL, dl = NULL;
		std::string key = "";
		do {
			asalt = new BYTE[salt_len + sizeof(DWORD)];
			if (asalt == NULL) {
				break;
			}
			memset(asalt, 0, salt_len + sizeof(DWORD));

			obuf = new BYTE[szHmac];
			if (obuf == NULL) {
				break;
			}
			memset(obuf, 0, szHmac);
			
			dl = new BYTE[szHmac];
			if (dl == NULL) {
				break;
			}
			memset(dl, 0, szHmac);

			status = TRUE;
			memcpy(asalt, salt, salt_len);
			for (DWORD i = 1; szLen > 0; ++i) {
				*(PDWORD)(asalt + salt_len) = _byteswap_ulong(i);
				memcpy(dl, HMAC_SHA512(password, pass_len, asalt, salt_len + 4).c_str(), szHmac);
				memcpy(obuf, dl, szHmac);
				for (DWORD k = 1; k < iteration; ++k) {
					memcpy(dl, HMAC_SHA512(password, pass_len, dl, szHmac).c_str(), szHmac);
					for (DWORD j = 0; j < szHmac; ++j) {
						obuf[j] ^= dl[j];
					}
					memcpy(dl, obuf, szHmac);
				}
				DWORD r = min(szLen, szHmac);
				key += std::string((char *)obuf, r);
				szLen -= r;
			}
		} while (FALSE);
		if (dl) {
			delete[] dl;
			dl = NULL;
		}
		if (obuf) {
			delete[] obuf;
			obuf = NULL;
		}
		if (asalt) {
			delete[] asalt;
			asalt = NULL;
		}
		return key;
	}

	static std::string HMAC_SHA1(const void* key, int key_len, const void* msg, int msg_len) {
		HMAC_CTX* ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, key, key_len, EVP_sha1(), NULL);
		HMAC_Update(ctx, (unsigned char*)msg, msg_len);
		unsigned char output[SHA_DIGEST_LENGTH] = { 0 };
		unsigned int output_length = 0;
		HMAC_Final(ctx, output, &output_length);
		HMAC_CTX_free(ctx);
		return std::string((char*)output, output_length);
	}

};


class StramSHA256 {

public:
	void Update(const char* str, int len) {
		SHA256_Update(&ctx, str, len);
	}
	
	char* GetValue() {
		SHA256_Final((unsigned char *)m_value, &ctx);
		return m_value;
	}

	StramSHA256() {
		memset(m_value, 0, SHA256_DIGEST_LENGTH);
		SHA256_Init(&ctx);
	}
	
	~StramSHA256() = default;

private:
	char m_value[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
};