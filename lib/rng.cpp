/*
 * rng.cpp
 *
 *  Created on: May 8, 2016
 *      Author: blake
 */
#include "rng.hpp"


// assume 32-bits during initialization
MT_CONST MersenneTwister::CONST = _INIT(MersenneTwister::_32BIT);
MersenneTwister::BITSIZE MersenneTwister::bitsize = _32BIT;

int MersenneTwister::index = CONST.N + 1;
uint64_t MersenneTwister::lower_mask = ((uint64_t) 1 << CONST.R) - 1;
uint64_t MersenneTwister::upper_mask = (!lower_mask) & CONST.LOWER_W_BITS_MASK;

// make state holder large enough to accommodate both 32 and 64 bit
uint64_t MersenneTwister::state[624] = {0};


// assign constants based on bitsize of MersenneTwister chosen
MT_CONST MersenneTwister::_INIT(BITSIZE bsz){
	MT_CONST _CONST;

	if(bsz == _32BIT){
		_CONST.W	= 32;
		_CONST.N	= 624;
		_CONST.M	= 397;
		_CONST.R	= 31;
		_CONST.A	= 0x9908B0DF;
		_CONST.U	= 11;
		_CONST.D	= 0xFFFFFFFF;
		_CONST.S	= 7;
		_CONST.B	= 0x9D2C5680;
		_CONST.T	= 15;
		_CONST.C	= 0xEFC60000;
		_CONST.L	= 18;
		_CONST.F	= 1812433253;
		_CONST.LOWER_W_BITS_MASK = LOWER_32_BITS_MASK;
	}
	else if(bsz == _64BIT){
		_CONST.W	= 64;
		_CONST.N	= 312;
		_CONST.M	= 156;
		_CONST.R	= 31;
		_CONST.A	= 0xB5026F5AA96619E9;
		_CONST.U	= 29;
		_CONST.D	= 0x5555555555555555;
		_CONST.S	= 17;
		_CONST.B	= 0x71D67FFFEDA60000;
		_CONST.T	= 37;
		_CONST.C	= 0xFFF7EEE000000000;
		_CONST.L	= 43;
		_CONST.F	= 6364136223846793005;
		_CONST.LOWER_W_BITS_MASK = LOWER_64_BITS_MASK;
	}

	return _CONST;
}

void MersenneTwister::set_bitsize(BITSIZE bsz){
	bitsize = bsz;

	CONST = _INIT(bitsize);

	index = CONST.N + 1;
	lower_mask = ((uint64_t) 1 << CONST.R) - 1;
	upper_mask = (!lower_mask) & CONST.LOWER_W_BITS_MASK;
}

void MersenneTwister::srand_mt(uint64_t seed){
	index = CONST.N;
	state[0] = seed;

	for(int i = 1; i < CONST.N; i++){
		uint64_t tmp = (CONST.F * (state[i-1] ^ (state[i-1] >> (CONST.W-2))) + i);
		state[i] = tmp & CONST.LOWER_W_BITS_MASK;
	}
}

void MersenneTwister::twist_mt(){
	for(int i = 0; i < CONST.N; i++){
		uint64_t x = (state[i] & upper_mask)
				+ (state[(i+1) % CONST.N] & lower_mask);

		uint64_t xA = x >> 1;

		if ((x % 2) != 0) { // lowest bit of x is 1
			xA = xA ^ CONST.A;
		}

		state[i] = state[(i + CONST.M) % CONST.N] ^ xA;
	}

	index = 0;
}

long int MersenneTwister::rand_mt(){
	 if (index >= CONST.N) {
		 if (index > CONST.N) {
		   cout << "MersenneTwister.rand_mt(): Error, generator was never seeded" << endl;
		   // Alternatively, seed with constant value; 5489 is used in reference C code[44]
		 }

		 twist_mt();
	 }

	  // Tempering
	 uint64_t y = state[index];
	 y = y ^ ((y >> CONST.U) & CONST.D);
	 y = y ^ ((y << CONST.S) & CONST.B);
	 y = y ^ ((y << CONST.T) & CONST.C);
	 y = y ^  (y >> CONST.L);

	 index++;

	 if(bitsize == _32BIT)
		 // cast to int first before we convert to long int in function return
		 return (int) (y & CONST.LOWER_W_BITS_MASK);

	 else if(bitsize == _64BIT)
		 return (long int) (y & CONST.LOWER_W_BITS_MASK);
}

