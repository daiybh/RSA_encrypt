#include "stdafx.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string>

int padding = RSA_PKCS1_PADDING;

//创建RSA
RSA * createRSA(unsigned char * key, bool bPublic)
{
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL)
	{
		printf("Failed to create key BIO");
		return 0;
	}
	if (bPublic)
	{
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	}
	else
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	if (rsa == NULL)
	{
		printf("Failed to create RSA");
	}

	return rsa;
}

//公钥加密
int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
	RSA * rsa = createRSA(key, true);
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

//私钥解密
int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
	RSA * rsa = createRSA(key, false);
	int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

//私钥加密
int private_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
	RSA * rsa = createRSA(key, false);
	int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

//公钥解密
int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
	RSA * rsa = createRSA(key, true);
	int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

// Base64 编码
void Base64Encode(const std::string &input, std::string &output)
{
	//编码表
	const char EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	//返回值
	size_t DataByte = input.size();
	const char* Data = input.data();
	std::string strEncode;
	unsigned char Tmp[4] = { 0 };
	int LineLength = 0;
	for (int i = 0; i < (int)(DataByte / 3); i++)
	{
		Tmp[1] = *Data++;
		Tmp[2] = *Data++;
		Tmp[3] = *Data++;
		strEncode += EncodeTable[Tmp[1] >> 2];
		strEncode += EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
		strEncode += EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
		strEncode += EncodeTable[Tmp[3] & 0x3F];
		if (LineLength += 4, LineLength == 76) { strEncode += ""; LineLength = 0; }
	}

	//对剩余数据进行编码
	int Mod = DataByte % 3;
	if (Mod == 1)
	{
		Tmp[1] = *Data++;
		strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
		strEncode += EncodeTable[((Tmp[1] & 0x03) << 4)];
		strEncode += "==";
	}
	else if (Mod == 2)
	{
		Tmp[1] = *Data++;
		Tmp[2] = *Data++;
		strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
		strEncode += EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xF0) >> 4)];
		strEncode += EncodeTable[((Tmp[2] & 0x0F) << 2)];
		strEncode += "=";
	}

	output = strEncode;
}

// Base64 解码
void Base64Decode(const std::string &input, std::string &output)
{
	//解码表
	const char DecodeTable[] =
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		62, // '+'
		0, 0, 0,
		63, // '/'
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // '0'-'9'
		0, 0, 0, 0, 0, 0, 0,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 'A'-'Z'
		0, 0, 0, 0, 0, 0,
		26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // 'a'-'z'
	};

	//返回值
	std::string strDecode;
	size_t DataByte = input.size();
	const char* Data = input.data();
	int nValue;
	size_t i = 0;
	while (i < DataByte)
	{
		if (*Data != '\r' && *Data != '\n')
		{
			nValue = DecodeTable[*Data++] << 18;
			nValue += DecodeTable[*Data++] << 12;
			strDecode += (nValue & 0x00FF0000) >> 16;
			if (*Data != '=')
			{
				nValue += DecodeTable[*Data++] << 6;
				strDecode += (nValue & 0x0000FF00) >> 8;
				if (*Data != '=')
				{
					nValue += DecodeTable[*Data++];
					strDecode += nValue & 0x000000FF;
				}
			}
			i += 4;
		}
		else// 回车换行,跳过
		{
			Data++;
			i++;
		}
	}
	output = strDecode;
}

void printLastError(char *msg)
{
	char * err = (char*)malloc(130);
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n", msg, err);
	free(err);
}

typedef enum
{
	DPSDK_PB_NORMAL = 1024,
	DPSDK_PB_NORMAL_FAST2 = DPSDK_PB_NORMAL * 2,
	DPSDK_PB_NORMAL_FAST4 = DPSDK_PB_NORMAL * 4,
	DPSDK_PB_NORMAL_FAST8 = DPSDK_PB_NORMAL * 8,
	DPSDK_PB_NORMAL_FAST16 = DPSDK_PB_NORMAL * 16,
	DPSDK_PB_NORMAL_SLOW2 = DPSDK_PB_NORMAL / 2,
	DPSDK_PB_NORMAL_SLOW4 = DPSDK_PB_NORMAL / 4,
	DPSDK_PB_NORMAL_SLOW8 = DPSDK_PB_NORMAL / 8,
	DPSDK_PB_NORMAL_SLOW16 = DPSDK_PB_NORMAL / 16,
}DPSDK_PLAYBACK_SPEED;

int main() {

	char plainText[2048 / 8] = "dahua2021"; //key length : 2048

	//公钥
	char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"\
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFwUp8e4fQ0vl6ipKd0sB3MqMNuH783zrAxoI3tCOKGUfNJMDJSJzxqydV7K4JJtbHEqyY4+ZFh93k3C4l1FjRwdqoOfdtlCcAyKNttvR49DsIdKissR5Z/2X6Z2E+MDBgjH/7n2kynn7kKvC07V5bf12vDYt4i+cn618brNifzwIDAQAB\n"\
		"-----END PUBLIC KEY-----\n";

	//私钥
	char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDuFJAQiU51sl8w56Ot822RZM99sUuUY9PJNNYj9H5F2zQqGwkzjnnUTde4sy + RPLMrq3VKF0b7DdP5F4nw2pvRfZpbdYQT1K9lPoDMtyGC7kEI599Zu0h7EhD7VUerP4XShqsKwb1x7DLdxarXZi3l2mnI7cPnd1SJXkCzIiQ//wIDAQAB"\
		"-----END RSA PRIVATE KEY-----\n";


	unsigned char encrypted[4098] = {0};
	unsigned char decrypted[4098] = {0};
	//======================================================
	//公钥加密，私钥解密
	int encrypted_length = public_encrypt((unsigned char*)plainText, strlen(plainText), (unsigned char*)publicKey, encrypted);
	if (encrypted_length == -1)
	{
		printLastError("Public Encrypt failed ");
		exit(0);
	}

	//公钥加密后的base64编码
	std::string outBaseStr = "";
	
	Base64Encode((char*)encrypted, outBaseStr);
	printf("public_encrypt:Encrypted length =%d, Encrypted Text = %s, outBaseStr = %s\n", encrypted_length, encrypted, outBaseStr.c_str());

	//int decrypted_length = private_decrypt(encrypted, encrypted_length, (unsigned char*)privateKey, decrypted);
	//if (decrypted_length == -1)
	//{
	//	printLastError("Private Decrypt failed ");
	//	exit(0);
	//}
	//printf("private_decrypt:Decrypted Length =%d, Decrypted Text =%s\n", decrypted_length, decrypted);

	////======================================================
	////私钥加密，公钥解密
	//memset(encrypted, 0, 4098);
	//memset(decrypted, 0, 4098);
	//encrypted_length = private_encrypt((unsigned char*)plainText, strlen(plainText), (unsigned char*)privateKey, encrypted);
	//if (encrypted_length == -1)
	//{
	//	printLastError("Private Encrypt failed");
	//	exit(0);
	//}
	//printf("private_encrypt: Encrypted length =%d, Encrypted Text = %s\n", encrypted_length, encrypted);

	//decrypted_length = public_decrypt(encrypted, encrypted_length, (unsigned char*)publicKey, decrypted);
	//if (decrypted_length == -1)
	//{
	//	printLastError("Public Decrypt failed");
	//	exit(0);
	//}
	//printf("public_decrypt Decrypted Length =%d, Decrypted Text =%s\n", decrypted_length, decrypted);

	getchar();
}

