/*
 * rng.cpp
 *
 *  Created on: May 8, 2016
 *      Author: blake
 */
#include "rng.hpp"


/* Challenge 21 */
/* MERSENNE-TWISTER */

// assume 32-bits during initialization

MT_CONST MT::CONST = _INIT(MT::_32BIT);
MT::BITSIZE MT::bitsize = _32BIT;

int MT::index = CONST.N + 1;
uint64_t MT::lower_mask = ((uint64_t) 1 << CONST.R) - 1;
uint64_t MT::upper_mask = (!lower_mask) & CONST.LOWER_W_BITS_MASK;

// make state holder large enough to accommodate both 32 and 64 bit
uint64_t MT::state[624] = {0};


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

void MersenneTwister::load_state(vector<uint64_t> new_state){
	// check that we have N elements exactly
	if(new_state.size() != MT::CONST.N){
		cout << "MT_hacker::clone_MT_from_output(): ERROR: input array is does not have "
				<< MT::CONST.N << " elements" << endl;
	}

	for(int i = 0; i < MT::CONST.N; i++){
		state[i] = new_state[i];
	}

	index = 0;
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
	long int result;

	if (index >= CONST.N) {
		 if (index > CONST.N) {
		   cout << "MersenneTwister.rand_mt(): WARNING: generator was never seeded" << endl;
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
	 result = y & CONST.LOWER_W_BITS_MASK;

	 index++;


	 if(bitsize == _32BIT)
		 // cast to int first before we convert to long int in function return
		 return (int) result;

	 else /*bitsize == _64BIT */
		 return (long int) result;
}


/* Exercise 22 */
long int MT_hacker::rand_wait_then_seed_with_time(){
	// converted from us to sec
	// wait between 1 and 2 seconds
	usleep(RNG::rand_in_range(1, 2) * 1000 * 1000);

	MersenneTwister::srand_mt(time(NULL));

	// converted from us to sec
	// wait between 1 and 2 seconds
	usleep(RNG::rand_in_range(1, 2) * 1000 * 1000);

	return MersenneTwister::rand_mt();
}


long int MT_hacker::crack_MT_seed(long int output){
	// from time we received rand_output, work backwards incrementally
	// seeding the Twister and checking the first value.
	// We keep working backwards until we find a match - then the current seed
	// must be the original seed

	long int cracked_seed = -1;
	bool success = false;

	for(long int seed = time(NULL); seed > time(NULL) - 1000*1000*10; seed--){
		MersenneTwister::srand_mt(seed);

		if(output == MersenneTwister::rand_mt()){
			success = true;
			cracked_seed = seed;
			break;
		}
	}

	return cracked_seed;
}

/* Exercise 23 */
uint64_t MT_hacker::untemper_MT_output(long int in){
	// convert long int to unsigned, binary form
	uint64_t input = ((uint64_t) in) & MT::CONST.LOWER_W_BITS_MASK;

	/* 4th temper step */
	uint64_t step4 = input ^ ((input >> MT::CONST.L));

	/* 3rd temper step */
	uint64_t step3 = step4 ^ ((step4 << MT::CONST.T) & MT::CONST.C);

	/* 2nd temper step */
	uint64_t step2 = step3; 								// bits 6-0 are already OK
	step2 = step3 ^ ((step2 << MT::CONST.S) & MT::CONST.B); // bits 14-0 will be OK
	step2 = step3 ^ ((step2 << MT::CONST.S) & MT::CONST.B); //bits 24-0  will be OK
	step2 = step3 ^ ((step2 << MT::CONST.S) & MT::CONST.B); //bits 30-0  will be OK
	step2 = step3 ^ ((step2 << MT::CONST.S) & MT::CONST.B); //bits 32-0  will be OK

	/* 1st temper step */
	uint64_t step1 = step2;									// bits 32-21 are already OK
	step1 = step2 ^ ((step1 >> MT::CONST.U) & MT::CONST.D); // bits 32-10 will be OK
	step1 = step2 ^ ((step1 >> MT::CONST.U) & MT::CONST.D); // bits 32-0 will be OK

	return step1;
}

vector<uint64_t> MT_hacker::clone_MT_from_output(vector<long int> outputs){
	if(outputs.size() != MT::CONST.N){
		cout << "MT_hacker::clone_MT_from_output(): ERROR: input array is does not have "
				<< MT::CONST.N << " elements" << endl;
	}

	vector<uint64_t> cloned_state;

	for(int i = 0; i < MT::CONST.N; i++){
		cloned_state.push_back( untemper_MT_output(outputs[i]) );
	}

	return cloned_state;
}


/* RNG HELPER FUNCTIONS */

int RNG::rand_in_range(int lbound, int ubound){
	return (rand() % (ubound - lbound)) + lbound;
}

char RNG::rand_ascii_char(){
	int rand_char = rand_in_range(0,255);

	return (char) rand_char;
}

char RNG::rand_base64_char(){
	int rand_char = rand_in_range(0, NUMBER_BASE64_CHARS - 1);

	return (char) encoding_table[rand_char];
}

Xstr RNG::rand_ascii_string(int num_bytes){
	// seed the rand() function with the current time.
	srand(time(NULL));

	Xstr rand_s;
	rand_s.resize(num_bytes, 0);

	// fill each byte of the key up with random results
	for(int i = 0; i < num_bytes; i++){
		rand_s[i] = (uint8_t) rand_in_range(0, 256);
	}

	return rand_s;
}
