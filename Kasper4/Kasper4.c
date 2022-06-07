// Kasper4 - Stuffit 4 Password Recovery
// Greg Esposito
// Designed to be used with MaskProcessor to emit passwords

#include <stdio.h>
#include <string.h>
#include <windows.h>

#pragma warning(disable:4996)

typedef struct StuffItDESKeySchedule {
	unsigned int subKeys[16][2];
} StuffItDESKeySchedule;

void CSSetUInt32BE(unsigned char* b, unsigned int n) { b[0] = (n >> 24) & 0xff; b[1] = (n >> 16) & 0xff; b[2] = (n >> 8) & 0xff; b[3] = n & 0xff; }
unsigned int CSUInt32BE(const unsigned char* b) { return ((unsigned int)b[0] << 24) | ((unsigned int)b[1] << 16) | ((unsigned int)b[2] << 8) | (unsigned int)b[3]; }

const unsigned char BitReverseTable256[] = {
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

unsigned int ReverseBits(unsigned int val) {
	unsigned int c = 0;
	c = (BitReverseTable256[val & 0xff] << 24) |
		(BitReverseTable256[(val >> 8) & 0xff] << 16) |
		(BitReverseTable256[(val >> 16) & 0xff] << 8) |
		(BitReverseTable256[(val >> 24) & 0xff]);

	return c;
}

unsigned int Nibble(const unsigned char key[8], int n) {
	return (key[(n & 0x0f) >> 1] >> (((n ^ 1) & 1) << 2)) & 0x0f;
}
void StuffItDESSetKey(const unsigned char key[8], StuffItDESKeySchedule* keySchedule) {
	for (int i = 0; i < 16; i++) {
		unsigned int subKey1 = ((Nibble(key, i) >> 2) | (Nibble(key, i + 13) << 2));
		subKey1 |= ((Nibble(key, i + 11) >> 2) | (Nibble(key, i + 6) << 2)) << 8;
		subKey1 |= ((Nibble(key, i + 3) >> 2) | (Nibble(key, i + 10) << 2)) << 16;
		subKey1 |= ((Nibble(key, i + 8) >> 2) | (Nibble(key, i + 1) << 2)) << 24;
		unsigned int subKey0 = ((Nibble(key, i + 9) | (Nibble(key, i) << 4)) & 0x3f);
		subKey0 |= ((Nibble(key, i + 2) | (Nibble(key, i + 11) << 4)) & 0x3f) << 8;
		subKey0 |= ((Nibble(key, i + 14) | (Nibble(key, i + 3) << 4)) & 0x3f) << 16;
		subKey0 |= ((Nibble(key, i + 5) | (Nibble(key, i + 8) << 4)) & 0x3f) << 24;

		subKey0 = ReverseBits(subKey0);
		subKey1 = ReverseBits(subKey1);
		keySchedule->subKeys[i][0] = subKey1;
		keySchedule->subKeys[i][1] = subKey0;
	}
}

const unsigned int DES_SPtrans[8][64] = {
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

void Encrypt(unsigned int* left, unsigned int right, unsigned int* subKey) {
	unsigned int u = right ^ subKey[0];
	unsigned int t = _rotr(right, 4) ^ subKey[1];

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

void StuffItDESCrypt(unsigned char data[8], StuffItDESKeySchedule* keySchedule, int enc) {
	unsigned int left = ReverseBits(CSUInt32BE(&data[0]));
	unsigned int right = ReverseBits(CSUInt32BE(&data[4]));

	right = _rotr(right, 29);
	left = _rotr(left, 29);

	if (enc) {
		Encrypt(&left, right, keySchedule->subKeys[0]);
		Encrypt(&right, left, keySchedule->subKeys[1]);
		Encrypt(&left, right, keySchedule->subKeys[2]);
		Encrypt(&right, left, keySchedule->subKeys[3]);
		Encrypt(&left, right, keySchedule->subKeys[4]);
		Encrypt(&right, left, keySchedule->subKeys[5]);
		Encrypt(&left, right, keySchedule->subKeys[6]);
		Encrypt(&right, left, keySchedule->subKeys[7]);
		Encrypt(&left, right, keySchedule->subKeys[8]);
		Encrypt(&right, left, keySchedule->subKeys[9]);
		Encrypt(&left, right, keySchedule->subKeys[10]);
		Encrypt(&right, left, keySchedule->subKeys[11]);
		Encrypt(&left, right, keySchedule->subKeys[12]);
		Encrypt(&right, left, keySchedule->subKeys[13]);
		Encrypt(&left, right, keySchedule->subKeys[14]);
		Encrypt(&right, left, keySchedule->subKeys[15]);
	}
	else  {
		Encrypt(&left, right, keySchedule->subKeys[15]);
		Encrypt(&right, left, keySchedule->subKeys[14]);
		Encrypt(&left, right, keySchedule->subKeys[13]);
		Encrypt(&right, left, keySchedule->subKeys[12]);
		Encrypt(&left, right, keySchedule->subKeys[11]);
		Encrypt(&right, left, keySchedule->subKeys[10]);
		Encrypt(&left, right, keySchedule->subKeys[9]);
		Encrypt(&right, left, keySchedule->subKeys[8]);
		Encrypt(&left, right, keySchedule->subKeys[7]);
		Encrypt(&right, left, keySchedule->subKeys[6]);
		Encrypt(&left, right, keySchedule->subKeys[5]);
		Encrypt(&right, left, keySchedule->subKeys[4]);
		Encrypt(&left, right, keySchedule->subKeys[3]);
		Encrypt(&right, left, keySchedule->subKeys[2]);
		Encrypt(&left, right, keySchedule->subKeys[1]);
		Encrypt(&right, left, keySchedule->subKeys[0]);
	}

	left = _rotr(left, 3);
	right = _rotr(right, 3);

	CSSetUInt32BE(&data[0], ReverseBits(right));
	CSSetUInt32BE(&data[4], ReverseBits(left));
}

void CharsToHex(unsigned char* s, int len, unsigned char* bytes) {
	// mapping of ASCII characters to hex values
	const unsigned char hashmap[] =
	{
	  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
	  0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
	  0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
	};

	unsigned char idx0, idx1;
	char pos;

	for (int i = 0; i < len; ++i)
		bytes[i] = 0;

	for (pos = 0; ((pos < (len * 2)) && (pos < strlen(s))); pos += 2) {
		idx0 = s[pos + 0] & 0x1F ^ 0x10;
		idx1 = s[pos + 1] & 0x1F ^ 0x10;
		
		bytes[pos / 2] = (hashmap[idx0] << 4) | hashmap[idx1];
	};
}

FILE *OpenLog() {
	#define WAIT_TIME 2000
	#define WAIT_TRIES 5

	const unsigned char* logFilename = "crack.log";
	FILE *file = fopen(logFilename, "a");
	int i = 0;

	while (file == NULL && ++i <= WAIT_TRIES) {
		Sleep(WAIT_TIME);
		file = fopen(logFilename, "a");
	}

	return file;
}

int main(int argc, char* argv[]) {
	#define MAX_PASS_LEN	64

	StuffItDESKeySchedule keySchedule;
	FILE *logFile;

	unsigned char passData[MAX_PASS_LEN + 1];
	int passLen, offset = 0;

	//const unsigned char mKey[8] = { 0x06, 0x59, 0xc2, 0xe6, 0xee, 0x79, 0x45, 0x4a }; // thea - Fax94 Archive
	//const unsigned char mKey[8] = { 0xc2, 0xe8, 0x7e, 0x7a, 0xee, 0x3f, 0xde, 0x3a }; // restricted sit
	//const unsigned char mKey[8] = { 0x86, 0x4e, 0xed, 0x03, 0xa9, 0xb4, 0xe8, 0x24 }; // florence - famantbox.sit
	//const unsigned char mKey[8] = { 0x4d, 0xda, 0xbd, 0x58, 0x5e, 0x0c, 0xfd, 0x55 }; // 12345678
	//const unsigned char mKey[8] = { 0xf6, 0x15, 0xd8, 0xac, 0x23, 0xbe, 0x32, 0xfe }; // abcdefghijkl

	unsigned char mKey[8];
	unsigned char archiveIV[8];

	for (int i = 0; i < MAX_PASS_LEN; ++i) passData[i] = 0;

	if (argc != 2 || strlen(argv[1]) != 16) {
		printf("Please enter an 8-byte mKey with leading zeros.\n");
		return 1;
	}

	CharsToHex(argv[1], 8, mKey);

	printf("mKey: %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", mKey[0], mKey[1], mKey[2], mKey[3], mKey[4], mKey[5], mKey[6], mKey[7]);
	fflush(stdout);

	while (fgets(passData, MAX_PASS_LEN, stdin)) {
		for (int i = 0; i < MAX_PASS_LEN ; ++i) {
			if (passData[i] == '\r' || passData[i] == '\n') {
				passData[i] = '\0';
				break;
			}
		}

		unsigned char archiveKey[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
		int x = 0;

		passLen = strlen(passData);

		StuffItDESSetKey(archiveKey, &keySchedule);

		do {
			unsigned char passBlock[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

			offset = x << 3;

			memcpy(passBlock, passData + offset, 8);

			archiveKey[0] ^= passBlock[0] & 0x7f;
			archiveKey[1] ^= passBlock[1] & 0x7f;
			archiveKey[2] ^= passBlock[2] & 0x7f;
			archiveKey[3] ^= passBlock[3] & 0x7f;
			archiveKey[4] ^= passBlock[4] & 0x7f;
			archiveKey[5] ^= passBlock[5] & 0x7f;
			archiveKey[6] ^= passBlock[6] & 0x7f;
			archiveKey[7] ^= passBlock[7] & 0x7f;

			StuffItDESCrypt(archiveKey, &keySchedule, 1);
		} while ((((passLen >> (3 + x))) << (3 + x++)) > 0 && passLen > 8);

		memcpy(archiveIV, mKey, 8);
		StuffItDESSetKey(archiveKey, &keySchedule);
		StuffItDESCrypt(archiveIV, &keySchedule, 0);

		unsigned char verifyBlock[8] = { 0, 0, 0, 0, 0, 0, 0, 4 };
		memcpy(verifyBlock, archiveIV, 4);
		StuffItDESSetKey(archiveKey, &keySchedule);
		StuffItDESCrypt(verifyBlock, &keySchedule, 1);

		if (memcmp(verifyBlock + 4, archiveIV + 4, 4) == 0) {
			printf("Hit: %s\n", passData);
			fflush(stdout);

			logFile = OpenLog();
			if (logFile == NULL) {
				printf("Cant't write to log!\n");
				return 1;
			}
			else {
				fprintf(logFile, "%s: %s\n", argv[1], passData);
				fclose(logFile);
			}
		}
	}
	printf("Done.\n");
	return 0;
}