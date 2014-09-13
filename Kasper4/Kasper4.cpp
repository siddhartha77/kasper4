#include "stdafx.h"
#include <stdio.h>
#include <cstdint> // For uint32_t
#include <string.h>
#include <iostream>
#include <iomanip>      // std::setprecision
#include <ctime>
#include <openssl/des.h>

typedef signed char        BOOL;
// BOOL is explicitly signed so @encode(BOOL) == "c" rather than "C" 
// even if -funsigned-char is used.
#define OBJC_BOOL_DEFINED

#define YES             (BOOL)1
#define NO              (BOOL)0

#define ROTATE(a,n) (((a)>>(n))+((a)<<(32-(n))))
#define READ_32BE(p) ((((p)[0]&0xFF)<<24)|(((p)[1]&0xFF)<<16)|(((p)[2]&0xFF)<<8)|((p)[3]&0xFF))
#define READ_64BE(p, l, r) { l=READ_32BE(p); r=READ_32BE((p)+4); }
#define WRITE_32BE(p, n) (p)[0]=(n)>>24,(p)[1]=(n)>>16,(p)[2]=(n)>>8,(p)[3]=(n)
#define WRITE_64BE(p, l, r) { WRITE_32BE(p, l); WRITE_32BE((p)+4, r); }

typedef struct StuffItDESKeySchedule
{
	uint32_t subkeys[16][2];
} StuffItDESKeySchedule;

/*
StuffItDES is a modified DES that ROLs the input, does the DES rounds
without IP, then RORs result.  It also uses its own key schedule.
It is only used for key management.
*/

DES_LONG _reverseBits(DES_LONG in)
{
	DES_LONG out = 0;
	int i;
	for (i = 0; i<32; i++)
	{
		out <<= 1;
		out |= in & 1;
		in >>= 1;
	}
	return out;
}

static void StuffItDESSetKey(const_DES_cblock key, DES_key_schedule* ks)
{
	int i;
	DES_LONG subkey0, subkey1;

#define NIBBLE(i) ((key[((i)&0x0F)>>1]>>((((i)^1)&1)<<2))&0x0F)
	for (i = 0; i<16; i++)
	{
		subkey1 = ((NIBBLE(i) >> 2) | (NIBBLE(i + 13) << 2));
		subkey1 |= ((NIBBLE(i + 11) >> 2) | (NIBBLE(i + 6) << 2)) << 8;
		subkey1 |= ((NIBBLE(i + 3) >> 2) | (NIBBLE(i + 10) << 2)) << 16;
		subkey1 |= ((NIBBLE(i + 8) >> 2) | (NIBBLE(i + 1) << 2)) << 24;
		subkey0 = ((NIBBLE(i + 9) | (NIBBLE(i) << 4)) & 0x3F);
		subkey0 |= ((NIBBLE(i + 2) | (NIBBLE(i + 11) << 4)) & 0x3F) << 8;
		subkey0 |= ((NIBBLE(i + 14) | (NIBBLE(i + 3) << 4)) & 0x3F) << 16;
		subkey0 |= ((NIBBLE(i + 5) | (NIBBLE(i + 8) << 4)) & 0x3F) << 24;
		ks->ks[i].deslong[1] = subkey1;
		ks->ks[i].deslong[0] = subkey0;
	}
#undef NIBBLE

	/* OpenSSL's DES implementation treats its input as little-endian
	(most don't), so in order to build the internal key schedule
	the way OpenSSL expects, we need to bit-reverse the key schedule
	and swap the even/odd subkeys.  Also, because of an internal rotation
	optimization, we need to rotate the second subkeys left 4.  None
	of this is necessary for a standard DES implementation.
	*/
	for (i = 0; i<16; i++)
	{
		/* Swap subkey pair */
		subkey0 = ks->ks[i].deslong[1];
		subkey1 = ks->ks[i].deslong[0];
		/* Reverse bits */
		subkey0 = _reverseBits(subkey0);
		subkey1 = _reverseBits(subkey1);
		/* Rotate second subkey left 4 */
		subkey1 = ROTATE(subkey1, 28);
		/* Write back OpenSSL-tweaked subkeys */
		ks->ks[i].deslong[0] = subkey0;
		ks->ks[i].deslong[1] = subkey1;
	}
}

#define PERMUTATION(a,b,t,n,m) \
	(t) = ((((a) >> (n)) ^ (b))&(m)); \
	(b) ^= (t); \
	(a) ^= ((t) << (n))

void _initialPermutation(DES_LONG *ioLeft, DES_LONG *ioRight)
{
	DES_LONG temp;
	DES_LONG left = *ioLeft;
	DES_LONG right = *ioRight;
	PERMUTATION(left, right, temp, 4, 0x0f0f0f0fL);
	PERMUTATION(left, right, temp, 16, 0x0000ffffL);
	PERMUTATION(right, left, temp, 2, 0x33333333L);
	PERMUTATION(right, left, temp, 8, 0x00ff00ffL);
	PERMUTATION(left, right, temp, 1, 0x55555555L);
	left = ROTATE(left, 31);
	right = ROTATE(right, 31);
	*ioLeft = left;
	*ioRight = right;
}

void _finalPermutation(DES_LONG *ioLeft, DES_LONG *ioRight)
{
	DES_LONG temp;
	DES_LONG left = *ioLeft;
	DES_LONG right = *ioRight;
	left = ROTATE(left, 1);
	right = ROTATE(right, 1);
	PERMUTATION(left, right, temp, 1, 0x55555555L);
	PERMUTATION(right, left, temp, 8, 0x00ff00ffL);
	PERMUTATION(right, left, temp, 2, 0x33333333L);
	PERMUTATION(left, right, temp, 16, 0x0000ffffL);
	PERMUTATION(left, right, temp, 4, 0x0f0f0f0fL);
	*ioLeft = left;
	*ioRight = right;
}
static void StuffItDESCrypt(DES_cblock data, DES_key_schedule* ks, BOOL enc)
{
	DES_LONG left, right;
	DES_cblock input, output;

	READ_64BE(data, left, right);

	/* This DES variant ROLs the input and RORs the output */
	left = ROTATE(left, 31);
	right = ROTATE(right, 31);

	/* This DES variant skips the initial permutation (and subsequent inverse).
	Since we want to use a standard DES library (which includes them), we
	wrap the encryption with the inverse permutations.
	*/
	_finalPermutation(&left, &right);

	WRITE_64BE(input, left, right);

	DES_ecb_encrypt(&input, &output, ks, enc);

	READ_64BE(output, left, right);

	_initialPermutation(&left, &right);

	left = ROTATE(left, 1);
	right = ROTATE(right, 1);

	WRITE_64BE(data, left, right);
}

using namespace std;
int main(int argc, char* argv[])
{
	DES_key_schedule ks;

	/* Start - Setup Timer */

	std::clock_t start;
	double duration;
	start = std::clock();

	/* End - Setup Timer */

	/* Start - Hash Length Check */ //Remove for a small ~10k jump

	size_t j;
	for (int i = 1; i < argc; i++) {
	j = strlen(argv[1]);
	if (j != 16){
	std::cout << argv[1] << " is " << j << " is not 16 characters long to be an MKEY!\n";
			return 0;
		}
	}

	/* End - Hash Length Check */

	/* Start - Line Entry and Count */
	char passworddata[40]; //Find max length of passwords - TODO
	size_t i;
	__int64 linecount = 0; // caps at 9,223,372,036,854,775,807, Mac uses long it but it resets count
	int billioncount = 0;
	//  printf("Enter a string: ");
	const_DES_cblock initialkey = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
	//const uint8_t mkey[8] = { 0x33, 0xe9, 0x37, 0x21, 0xbc, 0xa1, 0xda, 0x61 }; // UNKNOWN - 98MailOut
	//	const uint8_t mkey[8] = { 0x14, 0x34, 0x3b, 0xb8, 0xb4, 0xd0, 0x90, 0xaf }; // aaa Test file
	//	const uint8_t mkey[8] = { 0xa1, 0xbe, 0x48, 0x1e, 0x53, 0x46, 0x05, 0x1c }; // 29r65xw Foolproof install
		const uint8_t mkey[8] = { 0x06, 0x59, 0xc2, 0xe6, 0xee, 0x79, 0x45, 0x4a }; // thea - Fax94
	//	const uint8_t mkey[8] = { 0x2c, 0x91, 0xa6, 0xa9, 0x32, 0x29, 0xe6, 0x08 }; // thea - Fax95
	//	const uint8_t mkey[8] = { 0x3a, 0x96, 0x9d, 0x8a, 0xa2, 0x93, 0xea, 0x30 }; // UNKNOWN - FPDocs
	//	const uint8_t mkey[8] = { 0x02, 0xcc, 0x46, 0xa2, 0xd2, 0x36, 0x89, 0x6d }; // UNKNOWN - AllScores - ??? mira ??? - ??? ""8aq ???
		DES_cblock archivekey;
		DES_cblock archiveiv;

	while (fgets(passworddata, 40, stdin)){

		/* remove newline, if present */
		i = strlen(passworddata) - 1;
		if (passworddata[i] == '\n')
			passworddata[i] = '\0';
		
		linecount++;		
		if (linecount == 10000000){
			duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
			double linespersec = linecount / duration;
			std::cout << fixed << setprecision(0) << "10 million tries (" << linespersec << " l/s)\n";
		}
		if (linecount == 100000000){
			duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
			double linespersec = linecount / duration;
			std::cout << fixed << setprecision(0) << "100 million tries (" << linespersec << " l/s)\n";
		}
		if (linecount % 1000000000 == 0){
			billioncount++;
			duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
			double linespersec = linecount / duration;
			std::cout << fixed << setprecision(0) << billioncount << " billion tries (" << linespersec << " l/s)\n";
		}
		/* End- Line Entry */

		/* Start - DES Round 1 */

		DES_cblock passblock = { 0, 0, 0, 0, 0, 0, 0, 0 };
		//	printf("password: %s\n", [[passworddata description] UTF8String]);

	//	size_t length = i;//[passworddata length];
	//		printf("password length: %d", length);

	//	if (length > 8) length = 8;
	//		printf(" - password length post >8 check: %d\n", length);

	//	memcpy(passblock, passworddata, length);
		memcpy(passblock, passworddata, i);

//printf("password block def: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", passblock[0], passblock[1], passblock[2], passblock[3], passblock[4], passblock[5], passblock[6], passblock[7], passblock[8]);

		// Calculate archive key and IV from password and mkey

		//		uint8_t archivekey[8], archiveiv[8];
		//	const uint8_t initialkey[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
//printf("initialkey block def: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", initialkey[0], initialkey[1], initialkey[2], initialkey[3], initialkey[4], initialkey[5], initialkey[6], initialkey[7]);

		for (int i = 0; i < 8; i++) archivekey[i] = initialkey[i] ^ (passblock[i] & 0x7f);
//printf("archivekey raised def: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", archivekey[0], archivekey[1], archivekey[2], archivekey[3], archivekey[4], archivekey[5], archivekey[6], archivekey[7]);
		StuffItDESSetKey(initialkey, &ks);
		StuffItDESCrypt(archivekey, &ks, YES);

		// no change to initialkey after setdeskey

//printf("archivekey block def: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", archivekey[0], archivekey[1], archivekey[2], archivekey[3], archivekey[4], archivekey[5], archivekey[6], archivekey[7]);

		//printf("mkey hex+ascii: %s\n", [[mkey description] UTF8String]);

		// 161,000 lines/sec on X201 x64 Release
		
		memcpy(archiveiv, mkey, 8);
//printf("mkey block def: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n",	archiveiv[0], archiveiv[1], archiveiv[2], archiveiv[3], archiveiv[4], archiveiv[5], archiveiv[6], archiveiv[7]);
		StuffItDESSetKey(archivekey, &ks);
		StuffItDESCrypt(archiveiv, &ks, NO);

		// Verify the password.
		DES_cblock verifyblock = { 0, 0, 0, 0, 0, 0, 0, 4 };
		memcpy(verifyblock, archiveiv, 4); // Copies first 4 hex pairs into verifyblock (which has three zero pairs and 04 at the end)
//		printf("verify block 1: %02x\n", verifyblock);
//		 printf("archiveiv block 1: %02x\n", archiveiv);

		//original archiveiv
//printf("archiveiv block def: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", archiveiv[0], archiveiv[1], archiveiv[2], archiveiv[3], archiveiv[4], archiveiv[5], archiveiv[6], archiveiv[7]);

		//verifyblock with half of archiveiv data
//printf("verifyblock block 1: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", verifyblock[0], verifyblock[1], verifyblock[2], verifyblock[3], verifyblock[4], verifyblock[5], verifyblock[6], verifyblock[7]);

//		    printf("verify block pre-round: %s\n", verifyblock);
	//	   printf("archiveiv block pre-round: %s\n", archiveiv);
		StuffItDESSetKey(archivekey, &ks);
		StuffItDESCrypt(verifyblock, &ks, YES);

		// VerifyBlock has first four changed		   
//		 printf("verify block 2: %02x\n", verifyblock);
//printf("verifyblock block 2: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", verifyblock[0], verifyblock[1], verifyblock[2], verifyblock[3], verifyblock[4], verifyblock[5], verifyblock[6], verifyblock[7]);

		// ArchiveIV remains the same
//		    printf("archiveiv block 2: %02x\n", archiveiv);
//printf("archiveiv block def: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", archiveiv[0], archiveiv[1], archiveiv[2], archiveiv[3], archiveiv[4], archiveiv[5], archiveiv[6], archiveiv[7]);

		// Compare the end blocks, 0 is equal, != 0 is not equal
		if (memcmp(verifyblock + 4, archiveiv + 4, 4) != 0){
			//printf("Password is bad\n");
			//return nil;
		}
		else
		{
			//printf("Password is good\n");
			//printf("Success at: %s", passworddata);
			//std::cout << "Success at: " << passworddata << endl;
						duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
						double linespersec = linecount / duration;
					//	std::cout << fixed << setprecision(0) << " for " << argv[1] << " in " << duration << " seconds at line " << linecount << " (" << linespersec << " l/s)\n";
						std::cout << "Success at: " << passworddata << fixed << setprecision(0) << " for MKEY in " << duration << " seconds at line " << linecount << " (" << linespersec << " l/s)\n";
		}

	}
	/* Start - Timer Closeout */
	duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
	double linespersec = linecount / duration;
	std::cout << fixed << setprecision(0) << "Exhausted search of " << linecount << " lines in " << duration << " seconds (" << linespersec << " l/s)\n";
	/* End - Timer Closeout */
	return 0;
}