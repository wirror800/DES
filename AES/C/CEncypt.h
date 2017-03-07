#pragma once

#include <stdio.h>
#include <string>
#include "AES.h"

using namespace std;

class CEncypt
{
public:
	CEncypt(void);
	~CEncypt(void);

	void test();

	//加密函数
	int Encrypt(char* dst, const char* src, unsigned int len);
	int Encrypt(char* src, unsigned int len);
	//解密函数
	int Decrypt(char* dst, const char* src, unsigned int len);
	int Decrypt(char* src, unsigned int len);

private:
	unsigned char* m_Key;
};
