/*
 * rng.hpp
 *
 *  Created on: May 8, 2016
 *      Author: blake
 */
#ifndef LIB_RNG_HPP_
#define LIB_RNG_HPP_

#include <iostream>
#include <unistd.h>
#include "codec.hpp"


using namespace std;


// TODO: make sure system has uint64_t


#define LOWER_32_BITS_MASK 	0xFFFFFFFF;
#define LOWER_64_BITS_MASK	0xFFFFFFFFFFFFFFFF;;


// constants for MT algorithm
typedef struct {
	uint64_t W;
	uint64_t N;
	uint64_t M;
	uint64_t R;
	uint64_t A;
	uint64_t U;
	uint64_t D;
	uint64_t S;
	uint64_t B;
	uint64_t T;
	uint64_t C;
	uint64_t L;
	uint64_t F;
	uint64_t LOWER_W_BITS_MASK;
} MT_CONST;


class MT_hacker;


class MersenneTwister{
public:
	enum BITSIZE {_32BIT = 32, _64BIT = 64};

	MersenneTwister(BITSIZE bitsz);
	MersenneTwister(uint64_t seed = time(NULL), BITSIZE bitsz = _32BIT);

	void srand_mt(uint64_t seed);
	void load_state(vector<uint64_t> state);
	void twist_mt();
	void set_bitsize(BITSIZE bsz);
	long int rand_mt();

	static MT_CONST GEN_CONSTANTS(BITSIZE bitsz);

private:
	void _INIT(uint64_t seed, BITSIZE bitsz);

	 BITSIZE bitsize;
	 MT_CONST CONST;

	 // make state holder large enough to accommodate both 32 and 64 bit
	 uint64_t state[624];
	 int index;
	 uint64_t lower_mask;
	 uint64_t upper_mask;

	// make MT_hacker a friend so it can access CONSTANTS
	friend MT_hacker;
};

// typedef to shorten class name
typedef MersenneTwister MT;


class MT_hacker{
public:
	/* Exercise 22 */
	static long int rand_wait_then_seed_with_time();

	/* Exercise 22 */
	static vector<uint64_t> clone_MT_from_output(vector<long int> outputs, MT::BITSIZE bitsz);
	static long int crack_MT_seed(long int output);

private:
	static uint64_t untemper_MT_output(long int in, MT::BITSIZE bitsz);
};




/* Basic RNG utilities */
namespace RNG {
	int rand_in_range(int lbound, int ubound);
	char rand_ascii_char();
	char rand_base64_char();
	Xstr rand_ascii_string(int num_bytes);
};




#endif /* LIB_RNG_HPP_ */
