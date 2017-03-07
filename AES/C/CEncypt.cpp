#include "CEncypt.h"

#define MAXLEN 8192

CEncypt::CEncypt(void)
{
	m_Key = new unsigned char[16];

	unsigned char key[] = "bf1ff6b9a7142cee";

	memcpy(m_Key, key, 16);
}

CEncypt::~CEncypt(void)
{
	delete m_Key;
	m_Key = NULL;
}

void print(unsigned char* state)
{
	int i;
	for(i=0; i<16; i++)
	{
		printf("%s%X ",state[i]>15 ? "" : "0", state[i]);
	}
	printf("\n");
}

void CEncypt::test()
{
	printf(">>> test\n");

	unsigned char key[] = 
	{
		0xaa, 0x7e, 0x15, 0x16, 
		0x28, 0xae, 0xd2, 0xa6, 
		0xab, 0xf7, 0x15, 0x88, 
		0x09, 0xcf, 0x4f, 0xee
	};
	AES aes(key);

	unsigned char input[] = 
	{
		0x32, 0x43, 0xf6, 0xa8, 
		0x88, 0x5a, 0x30, 0x8d, 
		0x31, 0x31, 0x98, 0xa2, 
		0xe0, 0x37, 0x07, 0x34
	};
	printf("Input:\n");
	print(input);

	aes.Cipher(input);
	printf("After Cipher:\n");
	print(input);

	aes.InvCipher(input);
	printf("After InvCipher:\n");
	print(input);
	printf("\n");

	string str = "Hello World!";
	char buf[1024] = {0};
	memcpy(buf, str.c_str(), str.size());
	printf("[%s]\n", buf);

	for(int j=0; j<16; j++) printf("[%2X] ", (unsigned char)buf[j]);
	printf("\n");

	aes.Cipher((void *)buf, str.size());
	for(int j=0; j<16; j++) printf("[%2X] ", (unsigned char)buf[j]);
	printf("\n");

	aes.InvCipher((void *)buf, str.size());
	for(int j=0; j<16; j++) printf("[%2X] ", (unsigned char)buf[j]);
	printf("\n[%s]\n\n", buf);
}

//加密函数
int CEncypt::Encrypt(char* dst, const char* src, unsigned int len)
{
	if (len == 0)
		return 0;
	unsigned int t = len%16;
	len = t==0 ? len : len+16-t;

	char buf[MAXLEN] = {0};
	memcpy(buf, src, len);
	AES aes(m_Key);
	aes.Cipher((void *)buf, len);
	memcpy(dst, buf, len);
	return len;
}

int CEncypt::Encrypt(char* src, unsigned int len)
{
	if (len == 0)
		return 0;
	unsigned int t = len%16;
	len = t==0 ? len : len+16-t;

	AES aes(m_Key);
	aes.Cipher((void *)src, len);
	return len;
}

//解密函数
int CEncypt::Decrypt(char* dst, const char* src, unsigned int len)
{
	if (len == 0)
		return 0;
	unsigned int t = len%16;
	len = t==0 ? len : len+16-t;
	
	char buf[MAXLEN] = {0};
	memcpy(buf, src, len);
	AES aes(m_Key);
	aes.InvCipher((void *)buf, len);
	memcpy(dst, buf, len);
	return len;
}

int CEncypt::Decrypt(char* src, unsigned int len)
{
	if (len == 0)
		return 0;
	unsigned int t = len%16;
	len = t==0 ? len : len+16-t;

	AES aes(m_Key);
	aes.InvCipher((void *)src, len);
	return len;
}
