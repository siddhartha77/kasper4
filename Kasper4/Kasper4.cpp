// Kasper4 - Stuffit 4 Password Recovery
// Greg Esposito
// Designed to be used with MaskProcessor to emit passwords
// Currently can break find potential passwords of length 8 or lower

#include "stdafx.h"
#include <stdio.h>
#include <cstdint> // For uint32_t
#include <string.h>
#include <iostream>
#include <iomanip>      // std::setprecision
#include <ctime>

typedef signed char        BOOL;
// BOOL is explicitly signed so @encode(BOOL) == "c" rather than "C" 
// even if -funsigned-char is used.
#define OBJC_BOOL_DEFINED

#define YES             (BOOL)1
#define NO              (BOOL)0

typedef struct StuffItDESKeySchedule
{
	uint32_t subkeys[16][2];
} StuffItDESKeySchedule;

static inline uint32_t RotateRight(uint32_t val, int n) { return (val >> n) + (val << (32 - n)); }
static inline void CSSetUInt32BE(uint8_t *b, uint32_t n) { b[0] = (n >> 24) & 0xff; b[1] = (n >> 16) & 0xff; b[2] = (n >> 8) & 0xff; b[3] = n & 0xff; }
static inline uint32_t CSUInt32BE(const uint8_t *b) { return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3]; }

static const unsigned char BitReverseTable256[] =
{
	0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
	0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
	0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
	0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
	0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
	0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
	0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
	0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
	0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
	0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
	0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
	0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
	0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
	0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
	0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
	0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
};
// Added as part of option 2

static uint32_t ReverseBits(uint32_t val)
{
//	uint32_t res = 0;
//	for (int i = 0; i<32; i++)
//	{
//		res <<= 1;
//		res |= val & 1;
//		val >>= 1;
//	}
	// Original code above, benched ~220k l/s

	//val = ((val & 0x55555555) << 1) | ((val >> 1) & 0x55555555);
	//val = ((val & 0x33333333) << 2) | ((val >> 2) & 0x33333333);
	//val = ((val & 0x0F0F0F0F) << 4) | ((val >> 4) & 0x0F0F0F0F);
	//val = ((val & 0x00FF00FF) << 8) | ((val >> 8) & 0x00FF00FF);
	//val = (val << 16) | (val >> 16);
	// Option 1, benched ~389k l/s

	uint32_t c = 0;
	c = (BitReverseTable256[val & 0xff] << 24) |
		(BitReverseTable256[(val >> 8) & 0xff] << 16) |
		(BitReverseTable256[(val >> 16) & 0xff] << 8) |
		(BitReverseTable256[(val >> 24) & 0xff]);
	// Option 2, benched ~431k l/s

	return c;
//	return val; // option 1
//	return res; // original
}
static inline uint32_t Nibble(const uint8_t key[8], int n)
{
	return (key[(n & 0x0f) >> 1] >> (((n ^ 1) & 1) << 2)) & 0x0f;
}
static void StuffItDESSetKey(const uint8_t key[8], StuffItDESKeySchedule *ks)
{
	for (int i = 0; i<16; i++)
	{
		uint32_t subkey1 = ((Nibble(key, i) >> 2) | (Nibble(key, i + 13) << 2));
		subkey1 |= ((Nibble(key, i + 11) >> 2) | (Nibble(key, i + 6) << 2)) << 8;
		subkey1 |= ((Nibble(key, i + 3) >> 2) | (Nibble(key, i + 10) << 2)) << 16;
		subkey1 |= ((Nibble(key, i + 8) >> 2) | (Nibble(key, i + 1) << 2)) << 24;
		uint32_t subkey0 = ((Nibble(key, i + 9) | (Nibble(key, i) << 4)) & 0x3f);
		subkey0 |= ((Nibble(key, i + 2) | (Nibble(key, i + 11) << 4)) & 0x3f) << 8;
		subkey0 |= ((Nibble(key, i + 14) | (Nibble(key, i + 3) << 4)) & 0x3f) << 16;
		subkey0 |= ((Nibble(key, i + 5) | (Nibble(key, i + 8) << 4)) & 0x3f) << 24;

		// This is a little-endian DES implementation, so in order to get the
		// key schedule right, we need to bit-reverse and swap the even/odd
		// subkeys. This is not needed for a regular DES implementation.
		subkey0 = ReverseBits(subkey0);
		subkey1 = ReverseBits(subkey1);
		ks->subkeys[i][0] = subkey1;
		ks->subkeys[i][1] = subkey0;
	}
}

static const uint32_t DES_SPtrans[8][64] =
{
	{
		0x02080800, 0x00080000, 0x02000002, 0x02080802,
		0x02000000, 0x00080802, 0x00080002, 0x02000002,
		0x00080802, 0x02080800, 0x02080000, 0x00000802,
		0x02000802, 0x02000000, 0x00000000, 0x00080002,
		0x00080000, 0x00000002, 0x02000800, 0x00080800,
		0x02080802, 0x02080000, 0x00000802, 0x02000800,
		0x00000002, 0x00000800, 0x00080800, 0x02080002,
		0x00000800, 0x02000802, 0x02080002, 0x00000000,
		0x00000000, 0x02080802, 0x02000800, 0x00080002,
		0x02080800, 0x00080000, 0x00000802, 0x02000800,
		0x02080002, 0x00000800, 0x00080800, 0x02000002,
		0x00080802, 0x00000002, 0x02000002, 0x02080000,
		0x02080802, 0x00080800, 0x02080000, 0x02000802,
		0x02000000, 0x00000802, 0x00080002, 0x00000000,
		0x00080000, 0x02000000, 0x02000802, 0x02080800,
		0x00000002, 0x02080002, 0x00000800, 0x00080802,
	},
	{
		0x40108010, 0x00000000, 0x00108000, 0x40100000,
		0x40000010, 0x00008010, 0x40008000, 0x00108000,
		0x00008000, 0x40100010, 0x00000010, 0x40008000,
		0x00100010, 0x40108000, 0x40100000, 0x00000010,
		0x00100000, 0x40008010, 0x40100010, 0x00008000,
		0x00108010, 0x40000000, 0x00000000, 0x00100010,
		0x40008010, 0x00108010, 0x40108000, 0x40000010,
		0x40000000, 0x00100000, 0x00008010, 0x40108010,
		0x00100010, 0x40108000, 0x40008000, 0x00108010,
		0x40108010, 0x00100010, 0x40000010, 0x00000000,
		0x40000000, 0x00008010, 0x00100000, 0x40100010,
		0x00008000, 0x40000000, 0x00108010, 0x40008010,
		0x40108000, 0x00008000, 0x00000000, 0x40000010,
		0x00000010, 0x40108010, 0x00108000, 0x40100000,
		0x40100010, 0x00100000, 0x00008010, 0x40008000,
		0x40008010, 0x00000010, 0x40100000, 0x00108000,
	},
	{
		0x04000001, 0x04040100, 0x00000100, 0x04000101,
		0x00040001, 0x04000000, 0x04000101, 0x00040100,
		0x04000100, 0x00040000, 0x04040000, 0x00000001,
		0x04040101, 0x00000101, 0x00000001, 0x04040001,
		0x00000000, 0x00040001, 0x04040100, 0x00000100,
		0x00000101, 0x04040101, 0x00040000, 0x04000001,
		0x04040001, 0x04000100, 0x00040101, 0x04040000,
		0x00040100, 0x00000000, 0x04000000, 0x00040101,
		0x04040100, 0x00000100, 0x00000001, 0x00040000,
		0x00000101, 0x00040001, 0x04040000, 0x04000101,
		0x00000000, 0x04040100, 0x00040100, 0x04040001,
		0x00040001, 0x04000000, 0x04040101, 0x00000001,
		0x00040101, 0x04000001, 0x04000000, 0x04040101,
		0x00040000, 0x04000100, 0x04000101, 0x00040100,
		0x04000100, 0x00000000, 0x04040001, 0x00000101,
		0x04000001, 0x00040101, 0x00000100, 0x04040000,
	},
	{
		0x00401008, 0x10001000, 0x00000008, 0x10401008,
		0x00000000, 0x10400000, 0x10001008, 0x00400008,
		0x10401000, 0x10000008, 0x10000000, 0x00001008,
		0x10000008, 0x00401008, 0x00400000, 0x10000000,
		0x10400008, 0x00401000, 0x00001000, 0x00000008,
		0x00401000, 0x10001008, 0x10400000, 0x00001000,
		0x00001008, 0x00000000, 0x00400008, 0x10401000,
		0x10001000, 0x10400008, 0x10401008, 0x00400000,
		0x10400008, 0x00001008, 0x00400000, 0x10000008,
		0x00401000, 0x10001000, 0x00000008, 0x10400000,
		0x10001008, 0x00000000, 0x00001000, 0x00400008,
		0x00000000, 0x10400008, 0x10401000, 0x00001000,
		0x10000000, 0x10401008, 0x00401008, 0x00400000,
		0x10401008, 0x00000008, 0x10001000, 0x00401008,
		0x00400008, 0x00401000, 0x10400000, 0x10001008,
		0x00001008, 0x10000000, 0x10000008, 0x10401000,
	},
	{
		0x08000000, 0x00010000, 0x00000400, 0x08010420,
		0x08010020, 0x08000400, 0x00010420, 0x08010000,
		0x00010000, 0x00000020, 0x08000020, 0x00010400,
		0x08000420, 0x08010020, 0x08010400, 0x00000000,
		0x00010400, 0x08000000, 0x00010020, 0x00000420,
		0x08000400, 0x00010420, 0x00000000, 0x08000020,
		0x00000020, 0x08000420, 0x08010420, 0x00010020,
		0x08010000, 0x00000400, 0x00000420, 0x08010400,
		0x08010400, 0x08000420, 0x00010020, 0x08010000,
		0x00010000, 0x00000020, 0x08000020, 0x08000400,
		0x08000000, 0x00010400, 0x08010420, 0x00000000,
		0x00010420, 0x08000000, 0x00000400, 0x00010020,
		0x08000420, 0x00000400, 0x00000000, 0x08010420,
		0x08010020, 0x08010400, 0x00000420, 0x00010000,
		0x00010400, 0x08010020, 0x08000400, 0x00000420,
		0x00000020, 0x00010420, 0x08010000, 0x08000020,
	},
	{
		0x80000040, 0x00200040, 0x00000000, 0x80202000,
		0x00200040, 0x00002000, 0x80002040, 0x00200000,
		0x00002040, 0x80202040, 0x00202000, 0x80000000,
		0x80002000, 0x80000040, 0x80200000, 0x00202040,
		0x00200000, 0x80002040, 0x80200040, 0x00000000,
		0x00002000, 0x00000040, 0x80202000, 0x80200040,
		0x80202040, 0x80200000, 0x80000000, 0x00002040,
		0x00000040, 0x00202000, 0x00202040, 0x80002000,
		0x00002040, 0x80000000, 0x80002000, 0x00202040,
		0x80202000, 0x00200040, 0x00000000, 0x80002000,
		0x80000000, 0x00002000, 0x80200040, 0x00200000,
		0x00200040, 0x80202040, 0x00202000, 0x00000040,
		0x80202040, 0x00202000, 0x00200000, 0x80002040,
		0x80000040, 0x80200000, 0x00202040, 0x00000000,
		0x00002000, 0x80000040, 0x80002040, 0x80202000,
		0x80200000, 0x00002040, 0x00000040, 0x80200040,
	},
	{
		0x00004000, 0x00000200, 0x01000200, 0x01000004L,
		0x01004204, 0x00004004, 0x00004200, 0x00000000,
		0x01000000, 0x01000204, 0x00000204, 0x01004000,
		0x00000004, 0x01004200, 0x01004000, 0x00000204L,
		0x01000204, 0x00004000, 0x00004004, 0x01004204L,
		0x00000000, 0x01000200, 0x01000004, 0x00004200,
		0x01004004, 0x00004204, 0x01004200, 0x00000004L,
		0x00004204, 0x01004004, 0x00000200, 0x01000000,
		0x00004204, 0x01004000, 0x01004004, 0x00000204L,
		0x00004000, 0x00000200, 0x01000000, 0x01004004L,
		0x01000204, 0x00004204, 0x00004200, 0x00000000,
		0x00000200, 0x01000004, 0x00000004, 0x01000200,
		0x00000000, 0x01000204, 0x01000200, 0x00004200,
		0x00000204, 0x00004000, 0x01004204, 0x01000000,
		0x01004200, 0x00000004, 0x00004004, 0x01004204L,
		0x01000004, 0x01004200, 0x01004000, 0x00004004L,
	},
	{
		0x20800080, 0x20820000, 0x00020080, 0x00000000,
		0x20020000, 0x00800080, 0x20800000, 0x20820080,
		0x00000080, 0x20000000, 0x00820000, 0x00020080,
		0x00820080, 0x20020080, 0x20000080, 0x20800000,
		0x00020000, 0x00820080, 0x00800080, 0x20020000,
		0x20820080, 0x20000080, 0x00000000, 0x00820000,
		0x20000000, 0x00800000, 0x20020080, 0x20800080,
		0x00800000, 0x00020000, 0x20820000, 0x00000080,
		0x00800000, 0x00020000, 0x20000080, 0x20820080,
		0x00020080, 0x20000000, 0x00000000, 0x00820000,
		0x20800080, 0x20020080, 0x20020000, 0x00800080,
		0x20820000, 0x00000080, 0x00800080, 0x20020000,
		0x20820080, 0x00800000, 0x20800000, 0x20000080,
		0x00820000, 0x00020080, 0x20020080, 0x20800000,
		0x00000080, 0x20820000, 0x00820080, 0x00000000,
		0x20000000, 0x20800080, 0x00020000, 0x00820080,
	}
};

static inline void Encrypt(uint32_t *left, uint32_t right, uint32_t *subkey)
{
	uint32_t u = right^subkey[0];
	uint32_t t = RotateRight(right, 4) ^ subkey[1];
	//uint32_t t = _rotr(right, 4) ^ subkey[1];
	*left ^=
		DES_SPtrans[0][(u >> 2) & 0x3f] ^
		DES_SPtrans[2][(u >> 10) & 0x3f] ^
		DES_SPtrans[4][(u >> 18) & 0x3f] ^
		DES_SPtrans[6][(u >> 26) & 0x3f] ^
		DES_SPtrans[1][(t >> 2) & 0x3f] ^
		DES_SPtrans[3][(t >> 10) & 0x3f] ^
		DES_SPtrans[5][(t >> 18) & 0x3f] ^
		DES_SPtrans[7][(t >> 26) & 0x3f];
}

static void StuffItDESCrypt(uint8_t data[8],StuffItDESKeySchedule *ks,BOOL enc)
{
	uint32_t left = ReverseBits(CSUInt32BE(&data[0]));
	uint32_t right = ReverseBits(CSUInt32BE(&data[4]));

	right = RotateRight(right, 29);
	//right = _rotr(right, 29);
	left = RotateRight(left, 29);
	//left = _rotr(left, 29);

	if(enc) // BOOL YES
	{
	/*for (int i = 0; i<16; i += 2)
	{
		Encrypt(&left, right, ks->subkeys[i]);
		Encrypt(&right, left, ks->subkeys[i + 1]);
	}*/
		Encrypt(&left, right, ks->subkeys[0]);
		Encrypt(&right, left, ks->subkeys[1]);
		Encrypt(&left, right, ks->subkeys[2]);
		Encrypt(&right, left, ks->subkeys[3]);
		Encrypt(&left, right, ks->subkeys[4]);
		Encrypt(&right, left, ks->subkeys[5]);
		Encrypt(&left, right, ks->subkeys[6]);
		Encrypt(&right, left, ks->subkeys[7]);
		Encrypt(&left, right, ks->subkeys[8]);
		Encrypt(&right, left, ks->subkeys[9]);
		Encrypt(&left, right, ks->subkeys[10]);
		Encrypt(&right, left, ks->subkeys[11]);
		Encrypt(&left, right, ks->subkeys[12]);
		Encrypt(&right, left, ks->subkeys[13]);
		Encrypt(&left, right, ks->subkeys[14]);
		Encrypt(&right, left, ks->subkeys[15]);
	}
	else // BOOL NO
	{
	/*for (int i = 15; i>0; i -= 2)
	{
		Encrypt(&left, right, ks->subkeys[i]);
		Encrypt(&right, left, ks->subkeys[i - 1]);
	}*/
		Encrypt(&left, right, ks->subkeys[15]);
		Encrypt(&right, left, ks->subkeys[14]);
		Encrypt(&left, right, ks->subkeys[13]);
		Encrypt(&right, left, ks->subkeys[12]);
		Encrypt(&left, right, ks->subkeys[11]);
		Encrypt(&right, left, ks->subkeys[10]);
		Encrypt(&left, right, ks->subkeys[9]);
		Encrypt(&right, left, ks->subkeys[8]);
		Encrypt(&left, right, ks->subkeys[7]);
		Encrypt(&right, left, ks->subkeys[6]);
		Encrypt(&left, right, ks->subkeys[5]);
		Encrypt(&right, left, ks->subkeys[4]);
		Encrypt(&left, right, ks->subkeys[3]);
		Encrypt(&right, left, ks->subkeys[2]);
		Encrypt(&left, right, ks->subkeys[1]);
		Encrypt(&right, left, ks->subkeys[0]);
	}

	left = RotateRight(left, 3);
	//left = _rotr(left, 3);
	right = RotateRight(right, 3);
	//right = _rotr(right, 3);

	CSSetUInt32BE(&data[0], ReverseBits(right));
	CSSetUInt32BE(&data[4], ReverseBits(left));
}

using namespace std;
int main(int argc, char* argv[])
{
	StuffItDESKeySchedule ks;

	/* Start - Setup Timer */

	// clock_t is an alias for long whose max value according to my compiler's <climits> is 2147483647.

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
	const uint8_t initialkey[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

	// UNKNOWN OR TOO LONG PASSWORDS
	// const uint8_t mkey[8] = { 0x33, 0xe9, 0x37, 0x21, 0xbc, 0xa1, 0xda, 0x61 }; // UNKNOWN - 98MailOut Archive
	// const uint8_t mkey[8] = { 0x73, 0xb0, 0xb1, 0x87, 0xb9, 0xda, 0x62, 0x5d }; // 9a - FAILS DUE TO OVER THAN 8 CHARACTERS
	// const uint8_t mkey[8] = { 0x3a, 0x96, 0x9d, 0x8a, 0xa2, 0x93, 0xea, 0x30 }; // UNKNOWN - FPDocs Archive
	// const uint8_t mkey[8] = { 0x02, 0xcc, 0x46, 0xa2, 0xd2, 0x36, 0x89, 0x6d }; // UNKNOWN - AllScores Archive
	// const uint8_t mkey[8] = { 0xfb, 0xee, 0x95, 0xce, 0x65, 0x96, 0x4d, 0x8e }; // UNKNOWN - Receipt Registered 1.0 TT (Emailed) Archive

	// RECOVERED OR KNOWN PASSWORDS
	// const uint8_t mkey[8] = { 0x14, 0x34, 0x3b, 0xb8, 0xb4, 0xd0, 0x90, 0xaf }; // aaa Test file
	// const uint8_t mkey[8] = { 0x45, 0xe6, 0x78, 0xb0, 0x7d, 0x02, 0x03, 0x45 }; // Helen - Reg Reimer Email
	 const uint8_t mkey[8] = { 0x06, 0x59, 0xc2, 0xe6, 0xee, 0x79, 0x45, 0x4a }; // thea - Fax94 Archive
	// const uint8_t mkey[8] = { 0x2c, 0x91, 0xa6, 0xa9, 0x32, 0x29, 0xe6, 0x08 }; // thea - Fax95 Archive
	// const uint8_t mkey[8] = { 0xa1, 0xbe, 0x48, 0x1e, 0x53, 0x46, 0x05, 0x1c }; // 29r65xw Foolproof installer Archive


	uint8_t archivekey[8], archiveiv[8];

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

		uint8_t passblock[9] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };// was 8 with 8 0's
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

		//for (int i = 0; i < 8; i++) archivekey[i] = initialkey[i] ^ (passblock[i] & 0x7f);
		// Unrolled for loop
		archivekey[0] = initialkey[0] ^ (passblock[0] & 0x7f);
		archivekey[1] = initialkey[1] ^ (passblock[1] & 0x7f);
		archivekey[2] = initialkey[2] ^ (passblock[2] & 0x7f);
		archivekey[3] = initialkey[3] ^ (passblock[3] & 0x7f);
		archivekey[4] = initialkey[4] ^ (passblock[4] & 0x7f);
		archivekey[5] = initialkey[5] ^ (passblock[5] & 0x7f);
		archivekey[6] = initialkey[6] ^ (passblock[6] & 0x7f);
		archivekey[7] = initialkey[7] ^ (passblock[7] & 0x7f);
		
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
		uint8_t verifyblock[8] = { 0, 0, 0, 0, 0, 0, 0, 4 };
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
						printf("MKEY: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x", mkey[0], mkey[1], mkey[2], mkey[3], mkey[4], mkey[5], mkey[6], mkey[7]);
						std::cout << " - Success at: " << passworddata << fixed << setprecision(0) << " in " << duration << " seconds at line " << linecount << " (" << linespersec << " l/s)\n";
		}

	}
	/* Start - Timer Closeout */
	duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
	double linespersec = linecount / duration;
	std::cout << fixed << setprecision(0) << "Exhausted search of " << linecount << " lines in " << duration << " seconds (" << linespersec << " l/s)\n";
	/* End - Timer Closeout */
	return 0;
}