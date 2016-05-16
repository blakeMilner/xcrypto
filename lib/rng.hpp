/*
 * rng.hpp
 *
 *  Created on: May 8, 2016
 *      Author: blake
 */
#ifndef LIB_RNG_HPP_
#define LIB_RNG_HPP_

#include <iostream>

#include "codec.hpp"

using namespace std;

// TODO: make sure system has uint64_t


#define LOWER_32_BITS_MASK 	0xFFFFFFFF;
#define LOWER_64_BITS_MASK	0xFFFFFFFFFFFFFFFF;;

class MersenneTwister{

public:
	enum BITSIZE {_32BIT = 32, _64BIT = 64};

	static void srand_mt(uint64_t seed);
	static void twist_mt();
	static void set_bitsize(BITSIZE bsz);
	static long int rand_mt();

private:
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

	static BITSIZE bitsize;
	static MT_CONST CONST;
	static MT_CONST _INIT(BITSIZE bsz);

	 // make state holder large enough to accommodate both 32 and 64 bit
	static uint64_t state[624];
	static int index;
	static uint64_t lower_mask;
	static uint64_t upper_mask;
};

// typed to shorten class name
typedef MersenneTwister MT;

/* Basic RNG utilities */
namespace RNG {
	int rand_in_range(int lbound, int ubound);
	char rand_ascii_char();
	char rand_base64_char();
	Xstr rand_ascii_string(int num_bytes);
};


#endif /* LIB_RNG_HPP_ */
