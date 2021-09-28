#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

/* AES-128 simple implementation template and testing */

/*
Author: Miroslav Kallus, kallumir@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification:
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/
#define word(a0, a1, a2, a3) (a0 | (uint32_t)a1 << 8 | (uint32_t)a2 << 16 | (uint32_t)a3 << 24)

#define wbyte(w, pos) ((w >> (pos * 8)) & 0xff)
#define rotate_left(x, B) ( x << ( 8 * (B % 4) ) |  x >> ( 8 * ((4 - B) % 4 )))

/* AES Constants */

// forward sbox
const uint8_t SBOX[256] = {
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
}; 

uint32_t T0BOX [256] = {0,};
uint32_t T1BOX [256] = {0,};
uint32_t T2BOX [256] = {0,};
uint32_t T3BOX [256] = {0,};

const uint8_t rCon[12] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

/* AES state type */
typedef uint32_t t_state[4];

/* Helper functions */
void hexprint16(uint8_t *p) {
	for (int i = 0; i < 16; i++)
		printf("%02hhx ", p[i]);
	puts("");
}

void hexprintw(uint32_t w) {
	for (int i = 0; i < 32; i += 8)
		printf("%02hhx ", (w >> i) & 0xffU);
}

void hexprintws(uint32_t * p, int cnt) {
	for (int i = 0; i < cnt; i++)
		hexprintw(p[i]);
	puts("");
}
void printstate(t_state s) {
	hexprintw(s[0]);
	hexprintw(s[1]);
	hexprintw(s[2]);
	hexprintw(s[3]);
	puts("");
}
/*
uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3) {
	return a0 | (uint32_t)a1 << 8 | (uint32_t)a2 << 16 | (uint32_t)a3 << 24;
}
uint8_t wbyte(uint32_t w, int pos) {
	return (w >> (pos * 8)) & 0xff;
}
*/

// **************** AES  functions ****************
uint32_t subWord(uint32_t w) {
	return word(SBOX[wbyte(w, 0)], SBOX[wbyte(w, 1)], SBOX[wbyte(w, 2)], SBOX[wbyte(w, 3)]);
}

void subBytes(t_state s) {
	s[0] = subWord(s[0]);
	s[1] = subWord(s[1]);
	s[2] = subWord(s[2]);
	s[3] = subWord(s[3]);
}


void shiftRows(t_state s) {
	t_state tmp;

	for(int i = 0; i < 4; ++i)
		tmp[i] = s[i];
	s[0] = word(wbyte(tmp[0], 0), wbyte(tmp[1], 1), wbyte(tmp[2],2), wbyte(tmp[3],3));
	s[1] = word(wbyte(tmp[1], 0), wbyte(tmp[2], 1), wbyte(tmp[3],2), wbyte(tmp[0],3));
	s[2] = word(wbyte(tmp[2], 0), wbyte(tmp[3], 1), wbyte(tmp[0],2), wbyte(tmp[1],3));
	s[3] = word(wbyte(tmp[3], 0), wbyte(tmp[0], 1), wbyte(tmp[1],2), wbyte(tmp[2],3));


}

uint8_t xtime(uint8_t a) {
	uint16_t sh_a = (uint16_t)a << 1;
	if(sh_a > 255)
		return (uint8_t) sh_a ^ 0x1b;
	return sh_a;
}

// not mandatory - mix a single column
uint32_t mixColumn(uint32_t c) {
	uint32_t tmp = c;

	return word((xtime(wbyte(tmp,0)) ^ (xtime(wbyte(tmp, 1)) ^ wbyte(tmp, 1)) ^ wbyte(tmp, 2) ^ wbyte(tmp, 3)),
		   		 (wbyte(tmp,0) ^ xtime(wbyte(tmp, 1)) ^ (xtime(wbyte(tmp, 2)) ^ wbyte(tmp, 2)) ^ wbyte(tmp, 3)),
		   		 (wbyte(tmp,0) ^ wbyte(tmp, 1) ^ (xtime(wbyte(tmp, 2)) ^ (xtime(wbyte(tmp, 3))) ^ wbyte(tmp, 3))),
		   		 (((xtime(wbyte(tmp, 0)) ^ wbyte(tmp, 0)) ^ wbyte(tmp, 1)) ^ wbyte(tmp, 2) ^ xtime(wbyte(tmp, 3))));
}


void mixColumns(t_state s) {
	s[0] = mixColumn(s[0]);
	s[1] = mixColumn(s[1]);
	s[2] = mixColumn(s[2]);
	s[3] = mixColumn(s[3]);
}

/*
* Key expansion from 128bits (4*32b)
* to 11 round keys (11*4*32b)
* each round key is 4*32b
*/
void expandKey(uint32_t ek[44]) {
	/* ??? */

	for (int i = 1; i < 11; ++i)
	{
		uint32_t temp = word(wbyte(ek[4 * i - 1], 1), wbyte(ek[4 * i - 1], 2), wbyte(ek[4 * i - 1], 3), wbyte(ek[4 * i - 1], 0));
		temp = subWord(temp);
		ek[4 * i] = word((wbyte(temp, 0) ^ rCon[i]), wbyte(temp, 1), wbyte(temp, 2), wbyte(temp, 3)) ^ ek [4 * (i - 1)];
		ek[4 * i + 1] = ek[4 * i] ^ ek[4 * (i - 1) + 1];
		ek[4 * i + 2] = ek[4 * i + 1] ^ ek[4 * (i - 1) + 2];
		ek[4 * i + 3] = ek[4 * i + 2] ^ ek[4 * (i - 1) + 3];
	}
}


/* Adding expanded round key (prepared before) */
void addRoundKey(t_state s, uint32_t ek[], short round) {
	
		s[0] = s[0] ^ ek[round * 4 + 0];
		s[1] = s[1] ^ ek[round * 4 + 1];
		s[2] = s[2] ^ ek[round * 4 + 2];
		s[3] = s[3] ^ ek[round * 4 + 3];
}

void aes(uint8_t *in, uint8_t *out, uint8_t *skey)
{
	//... Initialize ...
	unsigned short round = 0;

	t_state state;

	state[0] = word(in[0],  in[1],  in[2],  in[3]);
	state[1] = word(in[4],  in[5],  in[6],  in[7]);
	state[2] = word(in[8],  in[9],  in[10],  in[11]);
	state[3] = word(in[12],  in[13],  in[14],  in[15]);


	uint32_t expKey[11 * 4];
	expKey[0] = word(skey[0], skey[1], skey[2], skey[3]);
	expKey[1] = word(skey[4], skey[5], skey[6], skey[7]);
	expKey[2] = word(skey[8], skey[9], skey[10], skey[11]);
	expKey[3] = word(skey[12], skey[13], skey[14], skey[15]);

	expandKey(expKey);

	addRoundKey(state, expKey, round);


	for (round = 1; round < 10; ++round)
	{
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, expKey, round);
	}

	subBytes(state);
	shiftRows(state);
	addRoundKey(state, expKey, round);



	for (int i = 0; i < 16; i++) {
		if (i < 4) out[i] = wbyte(state[0], i % 4);
		else if (i < 8) out[i] = wbyte(state[1], i % 4);
		else if (i < 12) out[i] = wbyte(state[2], i % 4);
		else out[i] = wbyte(state[3], i % 4);
	}
}

void genTBox()
{
	for (int i = 0; i < 256; ++i)
	{
		T0BOX[i] = word(
		   		 (((xtime(wbyte(SBOX[i], 0)) ^ wbyte(SBOX[i], 0)) ^ wbyte(SBOX[i], 1)) ^ wbyte(SBOX[i], 2) ^ xtime(wbyte(SBOX[i], 3))),
		   		 (wbyte(SBOX[i],0) ^ wbyte(SBOX[i], 1) ^ (xtime(wbyte(SBOX[i], 2)) ^ (xtime(wbyte(SBOX[i], 3))) ^ wbyte(SBOX[i], 3))),
		   		 (wbyte(SBOX[i],0) ^ xtime(wbyte(SBOX[i], 1)) ^ (xtime(wbyte(SBOX[i], 2)) ^ wbyte(SBOX[i], 2)) ^ wbyte(SBOX[i], 3)),
				 (xtime(wbyte(SBOX[i],0)) ^ (xtime(wbyte(SBOX[i], 1)) ^ wbyte(SBOX[i], 1)) ^ wbyte(SBOX[i], 2) ^ wbyte(SBOX[i], 3)));
		T1BOX[i] = rotate_left(T0BOX[i], 3);
		T2BOX[i] = rotate_left(T0BOX[i], 2);
		T3BOX[i] = rotate_left(T0BOX[i], 1);
	}
}

//****************************
// MAIN function: AES testing
//****************************
int main(int argc, char* argv[])
{

	int test_failed = 0;

	long int numOfRepetition = (argc > 1 && atoi(argv[1]) > 0) ? atoi(argv[1]) : 1000000; 
	clock_t t;
	uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uint8_t in[16] =  { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
	uint8_t out[16] = { 0, };
	genTBox();

	for (int i = 0; i < 256; ++i)
	{
		printf(" %08x ", T3BOX[i]);
		if((i % 8) == 7) printf("\n");
	}

	t = clock();

	for (long int i = 0; i < numOfRepetition; ++i)
	{
		aes(in, in, key);
	}
	t = clock() - t;	

	printf ("It took me %.0f ms.\n",((float)t)/(CLOCKS_PER_SEC/1000));
 	return  in[0];
}
