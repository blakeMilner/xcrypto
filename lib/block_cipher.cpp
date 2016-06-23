#include "block_cipher.hpp"


// TODO: put these in AES class
Xstr generate_random_AES_IV(){
	return RNG::rand_ascii_string(AES::BLOCKSIZE);
}

Xstr generate_random_AES_key(){
	return RNG::rand_ascii_string(AES::BLOCKSIZE);
}

Xstr generate_random_nonce(int nonce_size){
	return RNG::rand_ascii_string(nonce_size);
}

/* AES ENCRYPTION STUFF */

// definitions for constexpr members
constexpr uint8_t AES::rijndael_sbox[16][16];
constexpr uint8_t AES::inv_rijndael_sbox[16][16];

uint8_t AES::rjindael_sbox_lookup(uint8_t input){
	uint8_t digit1 = (input & 0xF0) >> 4;
	uint8_t digit2 = (input & 0x0F)     ;

	input = rijndael_sbox[digit1][digit2];

	return input;
}

uint8_t AES::inv_rjindael_sbox_lookup(uint8_t input){
	uint8_t digit1 = (input & 0xF0) >> 4;
	uint8_t digit2 = (input & 0x0F)     ;

	input = inv_rijndael_sbox[digit1][digit2];

	return input;
}

unsigned char AES::gmul(unsigned char a, unsigned char b) {
	unsigned char p = 0;
	unsigned char hi_bit_set;

	for(unsigned char counter = 0; counter < 8; counter++) {
		if((b & 1) == 1)
			p ^= a;

		hi_bit_set = (a & 0x80); /* hi bit */
		a <<= 1;

		if(hi_bit_set == 0x80) /* Rijndael's Galois field */
			a ^= 0x1b;

		b >>= 1;
	}

	return p;
}

// http://www.samiam.org/mix-column.html
Xstr AES::rjindael_mix_column(Xstr r) {
 	// make sure input CR_str is 16 bytes
	if(r.size() != 4){
		cout << "rjindael_mix_columns: input column size is not 4 bytes." << endl;

		return Xstr();
	}

    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    unsigned char a[4];
    unsigned char b[4];

    for(int c = 0; c < 4; c++) {
    	a[c] = r[c];
		b[c] = gmul(r[c], 2);
	}

    // used instead of successive calls to gmul() for speed
	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

    return r;
}

// http://www.samiam.org/mix-column.html
Xstr AES::rjindael_unmix_column(Xstr r) {
	 	// make sure input CR_str is 16 bytes
		if(r.size() != 4){
			cout << "rjindael_mix_columns: input column size is not 4 bytes." << endl;

			return Xstr();
		}

        // make output CR_str
        Xstr o = Xstr();
        o.resize(4, 0);

        /* The array 'a' is simply a copy of the input array 'r'
         * The array 'b' is each element of the array 'a' multiplied by 2
         * in Rijndael's Galois field
         * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
        unsigned char a[4];

        for(int c = 0; c < 4; c++) {
			a[c] = r[c];
		}

        r[0] = gmul(a[0], 14) ^ gmul(a[3], 9) ^ gmul(a[2], 13) ^ gmul(a[1], 11);
        r[1] = gmul(a[1], 14) ^ gmul(a[0], 9) ^ gmul(a[3], 13) ^ gmul(a[2], 11);
        r[2] = gmul(a[2], 14) ^ gmul(a[1], 9) ^ gmul(a[0], 13) ^ gmul(a[3], 11);
        r[3] = gmul(a[3], 14) ^ gmul(a[2], 9) ^ gmul(a[1], 13) ^ gmul(a[0], 11);

        return r;
}

Xstr AES::substitute_bytes(Xstr input){
	// apply nonlinear byte substitution
	// extract first and second digit and use it in LUT
	for(int i = 0; i < AES::BLOCKSIZE; i++){
		input[i] = rjindael_sbox_lookup( input[i] );
	}

	return input;
}

Xstr AES::unsubstitute_bytes(Xstr input){
	// apply nonlinear byte substitution
	// extract first and second digit and use it in LUT
	for(int i = 0; i < AES::BLOCKSIZE; i++){
		input[i] = inv_rjindael_sbox_lookup( input[i] );
	}

	return input;
}

Xstr AES::mix_columns(Xstr input){
	Xstr input_column = Xstr();
    input_column.resize(4, 0);

	// combine the 4 bytes in each column into a new 4-byte column using
	// an invertible linear transformation.
    for(int col = 0; col < 4; col++){
    	// copy column to contiguous
    	for(int row = 0; row < 4; row++){
    		input_column[row] = input[(col * 4) + row];
    	}

    	// mix column according to rjindael algorithm
    	Xstr mixed_column = rjindael_mix_column(input_column);

    	// copy mixed column back to original location
    	for(int row = 0; row < 4; row++){
    		input[(col * 4) + row] = mixed_column[row];
    	}
    }

    return input;
}

Xstr AES::unmix_columns(Xstr input){
	Xstr mixed_column = Xstr();
    mixed_column.resize(4, 0);

	// combine the 4 bytes in each column into a new 4-byte column using
	// an invertible linear transformation.
    for(int col = 3; col >= 0; col--){
    	// copy mixed column back to original location
    	for(int row = 3; row >= 0; row--){
    		mixed_column[row] = input[(col * 4) + row];
    	}

    	// mix column according to rjindael algorithm
    	Xstr input_column = rjindael_unmix_column(mixed_column);

    	// copy column to contiguous
    	for(int row = 3; row >= 0; row--){
    		input[(col * 4) + row] = input_column[row];
    	}
    }

    return input;
}

Xstr AES::shift_rows(Xstr input){
	Xstr output = Xstr();
    output.resize(AES::BLOCKSIZE, 0);

    // shift rows in a circular fashion - shift by row number
    // leave first row untouched
	output[0] = input[0];
	output[4] = input[4];
	output[8] = input[8];
	output[12] = input[12];

	output[1] = input[5];
	output[5] = input[9];
	output[9] = input[13];
	output[13] = input[1];

	output[2] = input[10];
	output[6] = input[14];
	output[10] = input[2];
	output[14] = input[6];

	output[3] = input[15];
	output[7] = input[3];
	output[11] = input[7];
	output[15] = input[11];

	return output;
}

Xstr AES::unshift_rows(Xstr input){
	Xstr output = Xstr();
    output.resize(AES::BLOCKSIZE, 0);

    // shift rows in a circular fashion - shift by row number
    // leave first row untouched
	output[0] = input[0];
	output[4] = input[4];
	output[8] = input[8];
	output[12] = input[12];

	output[5] = input[1];
	output[9] = input[5];
	output[13] = input[9];
	output[1] = input[13];

	output[10] = input[2];
	output[14] = input[6];
	output[2] = input[10];
	output[6] = input[14];

	output[15] = input[3];
	output[3] = input[7];
	output[7] = input[11];
	output[11] = input[15];

	return output;
}

// takes a four-byte character array, and performs a 1-byte left, circular rotate
void AES::rotate(unsigned char *in) {
	unsigned char a;
	a = in[0];

	for(unsigned char c = 0; c < 3 ; c++){
		in[c] = in[c + 1];
	}

	in[3] = a;

	return;
}

/* Calculate the rcon used in key expansion */
unsigned char AES::rcon(unsigned char in) {
	unsigned char c = 1;

	if(in == 0){
		return 0;
	}

	while(in != 1) {
		unsigned char b;
		b = c & 0x80;
		c <<= 1;

		if(b == 0x80) {
			c ^= 0x1b;
		}

		in--;
	}

	return c;
}

/* This is the core key expansion, which, given a 4-byte value,
 * does some scrambling */
void AES::schedule_core(unsigned char *in, unsigned char i) {
	char a;

	/* Rotate the input 8 bits to the left */
	rotate(in);

	/* Apply Rijndael's s-box on all 4 bytes */
	for(a = 0; a < 4; a++){
		in[a] = rjindael_sbox_lookup(in[a]);
	}

	/* On just the first byte, add 2^i to the byte */
	in[0] ^= rcon(i);
}

// expand 128-bit key into 10 other round keys
vector<string> AES::expand_key(unsigned char *input) {
	unsigned char t[4];

	/* c is 16 because the first sub-key is the user-supplied key */
	unsigned char c = 16;
	unsigned char i = 1;
	unsigned char a;

	// buffer for all keys
	unsigned char in[176] = {0};

	// copy in master key into buffer for all keys
	for(int i = 0; i < 16; i++){
		in[i] = input[i];
	}

	/* We need 11 sets of sixteen bytes each for 128-bit mode */
	while(c < 176) {
		/* Copy the temporary variable over from the last 4-byte
		 * block */
		for(a = 0; a < 4; a++){
			t[a] = in[a + c - 4];
		}

		/* Every four blocks (of four bytes),
		 * do a complex calculation */
		if(c % 16 == 0) {
			schedule_core(t, i);
			i++;
		}

		for(a = 0; a < 4; a++) {
			in[c] = in[c - 16] ^ t[a];
			c++;
		}
	}

	// TODO: change all resize operations to this format
	string all_keys(176, 0);

	// copy c string "in" into "all_keys" manually because giving it to the string
	// contructor will fail if "in" contains a 0 - interpreted as delimiter \0
	for(int i = 0; i < 176; i++){
		all_keys[i] = in[i];
	}

	vector<string> expanded_keys;

	// fill vector of up with substrings of main buffer - these are keys
	// for different rounds
	for(int i = 0; i < 11; i++){
	    expanded_keys.push_back( all_keys.substr(i * 16, 16) );
	}

	return expanded_keys;
}

// we only need one version of this for both encrypting/decrypting
// we always xor the input with the key
Xstr AES::add_round_key(Xstr plaintext, const vector<string>& key, int round){
	if(plaintext.size() != AES::BLOCKSIZE){
		cout << "rjindael_appl_round_key(): message size is not 16 bytes!" << endl;

		return string();
	}

	// xor the input text with the key for the corresponding round
	Xstr ciphertext = plaintext ^ key[round];

	return ciphertext;
}

// based on the Rjindael algorithm
Xstr AES::encrypt(Xstr plaintext, Xstr key){
	if(plaintext.size() < AES::BLOCKSIZE){
		plaintext = plaintext.add_padding(Xstr::PKCS7_PADDING, AES::BLOCKSIZE);
	}
	else if(plaintext.size() > AES::BLOCKSIZE){
		cout << "AES_cipher(): input plaintext size is " << plaintext.size()
			 << ", truncating to " << AES::BLOCKSIZE << endl;

		// truncate message
		plaintext = plaintext.substr(0, AES::BLOCKSIZE);
	}

	if(key.size() != AES::BLOCKSIZE){
		cout << "AES_cipher(): key size is not 16 bytes!" << endl;

		return string();
	}

	// expand key - input as low level c string.
	// Must cast because return value is const char*
	vector<string> round_keys = expand_key( (unsigned char*) key.as_ascii().c_str() );

	// working string for cipher
	Xstr ciphertext = plaintext.as_ascii();
    // initially XOR the input text with the key
    ciphertext = add_round_key( ciphertext, round_keys, 0 );

	for(int round = 1; round <= 10; round++){
		ciphertext = substitute_bytes(ciphertext);
		ciphertext = shift_rows(ciphertext);

		// don't mix columns on last round!
		if(round < 10){
			ciphertext = mix_columns(ciphertext);
		}

		ciphertext = add_round_key( ciphertext, round_keys, round );
	}

	return ciphertext;
}

// based on the Rjindael algorithm
Xstr AES::decrypt(Xstr ciphertext, Xstr key){
	if(ciphertext.size() < AES::BLOCKSIZE){
		ciphertext = ciphertext.add_padding(Xstr::PKCS7_PADDING, AES::BLOCKSIZE);
	}
	else if(ciphertext.size() > AES::BLOCKSIZE){
		cout << "AES_cipher(): input ciphertext size is " << ciphertext.size()
			 << ", truncating to 16." << endl;

		// truncate message
		ciphertext = ciphertext.substr(0, AES::BLOCKSIZE);
	}

	if(key.size() != AES::BLOCKSIZE){
		cout << "AES_cipher(): key size is not 16 bytes!" << endl;

		return string();
	}

	// expand key - input as low level c string.
	// Must cast because return value is const char*
	// Must go backwards through round_keys when decrypting
	vector<string> round_keys = expand_key( (unsigned char*) key.as_ascii().c_str() );

	// working string for cipher
	Xstr plaintext = ciphertext;

    //  go backwards through rounds and keys this time
	// this is merely a reversal of the methods found in the encrypt function
	for(int round = 10; round >= 1; round--){
		plaintext = add_round_key( plaintext, round_keys, round );

		// don't unmix columns on last round encrypting/first round of decrypting!
		if(round < 10){
			plaintext = unmix_columns(plaintext);
		}

		plaintext = unshift_rows(plaintext);
		plaintext = unsubstitute_bytes(plaintext);
	}

    // account for the initial XOR between input message and the master key
    plaintext = add_round_key( plaintext, round_keys, 0 );

	return plaintext;
}

// DES algorithms
Xstr DES::encrypt(Xstr plaintext, Xstr key){
	return Xstr();
}

Xstr DES::decrypt(Xstr ciphertext, Xstr key){
	return Xstr();
}

bool detect_ECB_AES_encryption(Xstr message){
    int blocks_count = message.size() / AES::BLOCKSIZE;
    int matches = 0;

    set<Xstr> all_blocks;

    // add all of the ciphertext blocks within the message into a set
    for (int index = 0; index < blocks_count; index++){
		Xstr block = message.substr(index * AES::BLOCKSIZE, AES::BLOCKSIZE);

		all_blocks.insert(block);
    }

    // if a duplicate ciphertext block was inserted, the size will be less than expected
    if(all_blocks.size() != blocks_count){
    	return true;
    }
	// if the size is the same, then there are no duplicate blocks
	// we assume there is no ECB encryption since there are no patterns
    else{
		return false;
    }
}

Xstr encrypt_using_CBC_or_ECB(Xstr message){
	int num_rand_prefix_bytes = RNG::rand_in_range(5, 10);
	int num_rand_suffix_bytes = RNG::rand_in_range(5, 10);

	Xstr prefix_string = RNG::rand_ascii_string(num_rand_prefix_bytes);
	Xstr suffix_string = RNG::rand_ascii_string(num_rand_suffix_bytes);

	Xstr appended_message = prefix_string + message + suffix_string;
	appended_message = appended_message.add_padding(Xstr::PKCS7_PADDING, AES::BLOCKSIZE); // pad appended message up to even block size

	Xstr rand_key = generate_random_AES_key();

	bool encrypt_using_ECB = rand() % 2;

	if(encrypt_using_ECB){
		return BlockCipher::encrypt(ECB_ENCRYPT, appended_message, rand_key);
	}
	else{
		Xstr rand_IV = generate_random_AES_IV();

		return BlockCipher::encrypt(CBC_ENCRYPT, appended_message, rand_key, rand_IV);
	}
}






///////// next: make an attribute for CR_str that tells what kind of encryption it has
////////// when detect ECB_CBC is used, it sets this attribute


// accepts a function pointer that implements an arbitrary encryption fucntion
// inputs - message to be encrypted
// outputs - encrypted message
EncryptType detect_ECB_or_CBC_encryption(Xstr (*encryption_fnc)(Xstr message)){
	// no matter what gets prepended/appended, 2nd and 3rd block will be all 0's
	// because of size = 48
	Xstr message = Xstr();
	message.resize(48, 0);

	Xstr encrypted_message = encryption_fnc(message);

	if(encrypted_message.get_single_block(1) == encrypted_message.get_single_block(2)){
//		cout << "ECB" << endl;
		return EncryptType::ECB_ENCRYPT;
	}
	else{
//		cout << "CBC" << endl;
		return EncryptType::CBC_ENCRYPT;
	}
}

/* Challenge 12 */
Xstr append_unknown_string_and_encrypt_ECB(Xstr message){
	// generate unknown key only once
	static Xstr rand_key = generate_random_AES_key();
	// create unknown string once
	static Xstr unknown_string = Xstr("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
												"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
												"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
												"YnkK", Xstr::BASE64_ENCODED);

	return BlockCipher::encrypt(ECB_ENCRYPT, message + unknown_string, rand_key);
}

Xstr byte_at_a_time_ECB_decrypt_simple(){
	Xstr (*blackbox)(Xstr);
	blackbox = append_unknown_string_and_encrypt_ECB;

	/* First, find the block size of the cipher by feeding in successive test characters */
	Xstr known_string = Xstr("A");
	Xstr new_cipher = blackbox(known_string);
	int block_size = 0;
	int last_size = 0;
	Xstr unknown_str_new_block = Xstr();

	/* find unknown string size by feeding in empty string */
	int unknown_string_size = blackbox( Xstr() ).size();
	int unknown_string_blocks = ceil(unknown_string_size / AES::BLOCKSIZE);

	do{
		last_size = new_cipher.size();
		known_string += Xstr("A");
		new_cipher = blackbox(known_string);
		block_size++;
	}
	while(new_cipher.size() == last_size);

	/* Verify that the function is using ECB */
	if(EncryptType::ECB_ENCRYPT != detect_ECB_or_CBC_encryption(blackbox)){
		cout << "byte_at_a_time_ECB_decrypt_simple(): function is not using ECB encryption." << endl;

		return Xstr();
	}

	/* Solve each block consecutively, solving one byte at a time */
	Xstr previous_blocks = Xstr();
	for(int blk = 0; blk < unknown_string_blocks; blk++){
		unknown_str_new_block = Xstr();
		
		for(int byte = AES::BLOCKSIZE - 1; byte >= 0; byte--){
			// make partial string with dummy chars (A's)
			known_string = string(byte, 'A');

			// encrypt once using partial string
			Xstr encrypted_actual = blackbox(known_string);

			// add known bytes to end of test string - do this after we compute encrypted message we compare test cases to
			known_string += previous_blocks;

			// add different byte values to end of known_string, see if this matches known_string with no extra byte
			Xstr known_string_guess;
			Xstr prefix = known_string + unknown_str_new_block;
			
			for(char c = 0; c < 256; c++){
				known_string_guess = prefix + string(1, c); // add new guess character to end of string

				// encrypt our new guess
				Xstr encrypted_guess = blackbox(known_string_guess);

				// if the actual and guessed blocks match, then we've found the next byte of unkown_string
				if(encrypted_actual.get_single_block(blk) == encrypted_guess.get_single_block(blk)){
					unknown_str_new_block += c;
					break;
				}
			}
		}

		previous_blocks += unknown_str_new_block;
	}

	return previous_blocks;
}

/* Challenge 14 */
// TODO: there is no prefix being added here!
Xstr append_unknown_string_random_prefix_and_encrypt_ECB(Xstr message){
	// generate unknown key only once
	static Xstr rand_key = generate_random_AES_key();
	// create unknown string once
	static Xstr unknown_string = Xstr("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
												"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
												"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
												"YnkK", Xstr::BASE64_ENCODED);

	return BlockCipher::encrypt(ECB_ENCRYPT, message + unknown_string, rand_key);
}

Xstr byte_at_a_time_ECB_decrypt_hard(){
	Xstr (*blackbox)(Xstr);
	blackbox = append_unknown_string_random_prefix_and_encrypt_ECB;

	/* First, find the block size of the cipher by feeding in successive test characters */
	Xstr known_string = Xstr("A");
	Xstr new_cipher = blackbox(known_string);
	int block_size = 0;
	int last_size = 0;
	Xstr unknown_str_new_block = Xstr();

	/* find unknown string size by feeding in empty string */
	int unknown_string_size = blackbox( Xstr() ).size();
	int unknown_string_blocks = unknown_string_size / AES::BLOCKSIZE;

	// find block size
	do{
		last_size = new_cipher.size();
		known_string += Xstr("A");
		new_cipher = blackbox(known_string);
		block_size++;
	}
	while(new_cipher.size() == last_size);

	/* Verify that the function is using ECB */
	if(EncryptType::ECB_ENCRYPT != detect_ECB_or_CBC_encryption(blackbox)){
		cout << "byte_at_a_time_ECB_decrypt_simple(): function is not using ECB encryption." << endl;

		return Xstr();
	}

	/* Solve each block consecutively, solving one byte at a time */
	Xstr previous_blocks = Xstr();
	for(int blk = 0; blk < unknown_string_blocks; blk++){
		unknown_str_new_block = Xstr();

		for(int byte = AES::BLOCKSIZE - 1; byte >= 0; byte--){
			// make partial string with dummy chars (A's)
			known_string = string(byte, 'A');

			// encrypt once using partial string
			Xstr encrypted_actual = blackbox(known_string);

			// add known bytes to end of test string - do this after we compute encrypted message we compare test cases to
			known_string += previous_blocks;

			// add different byte values to end of known_string, see if this matches known_string with no extra byte
			Xstr known_string_guess;
			Xstr prefix = known_string + unknown_str_new_block;

			//cout << unknown_str_new_block.as_base64() << " " << endl;

			for(char c = 0; c < 256; c++){
				known_string_guess = prefix + c; // add new guess character to end of string

				// encrypt our new guess
				Xstr encrypted_guess = blackbox(known_string_guess);

				// if the actual and guessed blocks match, then we've found the next byte of unkown_string
				if(encrypted_actual.get_single_block(blk) == encrypted_guess.get_single_block(blk)){
					unknown_str_new_block += c;
					break;
				}
			}
		}

		previous_blocks += unknown_str_new_block;
	}
	
	// TODO: Have these functions check if padding is present and then remove
	//	previous_blocks = previous_blocks.remove_padding(CR_str::UNKNOWN_PADDING);

	return previous_blocks;
}

/* Challenge 17 */

BlockCipher::CipherData pad_random_string_and_encrypt_CBC(){
	static const string unknown_strings[9] = {
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
	};

	// generate unknown key only once
	static Xstr rand_key = generate_random_AES_key();
	// generate unknown key only once
	static Xstr rand_IV = generate_random_AES_IV();

	// create unknown string only once, by picking from list of 10
	static int i = RNG::rand_in_range(0, 8);
	static string random_string = unknown_strings[i];

	static Xstr unknown_string = Xstr(random_string, Xstr::BASE64_ENCODED);

	unknown_string = unknown_string.add_padding(Xstr::ZERO_PADDING, AES::BLOCKSIZE);

	BlockCipher::CipherData out;

	out.message = BlockCipher::encrypt(CBC_ENCRYPT, unknown_string, rand_key, rand_IV);
	out.key = rand_key;
	out.IV_nonce = rand_IV;

	return out;
}

/* Challenge 17 */

Xstr break_AES_CBC_via_server_leak(BlockCipher::CipherData cipher_info){
	Xstr cipher = cipher_info.message;
	int num_ciphers = cipher.get_num_blocks();

	Xstr hacked_cipher;
	Xstr curr_cipher;
	Xstr orig_hacked_cipher;

	// make holder for 1 block intermediate state
	Xstr intermediate;
	intermediate.fill(AES::BLOCKSIZE, 0);

	// make output one less blocksize than input cipher - we can't
	// figure out the first block with this hack
	Xstr output;
	output.fill((num_ciphers - 1) * AES::BLOCKSIZE, 0);

	// padding value, to be incremented
	uint8_t pad_value = 0x01;

	/*
	 * Go to (num_ciphers-1) because we can't decode the first ciphertext block.
	 * Before, we manipulated the intermediate state via corrupting the previous
	 * ciphertext block. But for the first block, we can't manipulate the IM
	 * state because it is the IV, which we don't know.
	 */
	for(int c = 0; c < num_ciphers - 1; c++){
		 // padding value gets incremented as we move down block, per PKCS7
		uint8_t pkcs7_pad_value = 0x01;

		// get cipher we're trying to solve and cipher we will manipulate
		int offset = (num_ciphers - c - 2) * AES::BLOCKSIZE;
		curr_cipher 	= cipher.get_single_block(num_ciphers - c - 1);
		hacked_cipher 	= cipher.get_single_block(num_ciphers - c - 2);
		orig_hacked_cipher = hacked_cipher;

		// loop through each bit of target cipher, starting with high bit
		for(int curr_bit = AES::BLOCKSIZE - 1; curr_bit >= 0; curr_bit--){
			// fill altered cipher block with the XOR'd equivalent of the padding
			// we need this to make previously found blocks into target padding value
			for(int i = AES::BLOCKSIZE - 1; i > curr_bit; i--){
				hacked_cipher[i] = pkcs7_pad_value ^ intermediate[i];
			}

			// loop through all possible ascii characters that will produce
			// a valid padding byte
			for(int x = 0; x < 256; x++){
				hacked_cipher[curr_bit] = x;

				cipher_info.message = hacked_cipher + curr_cipher;

				// if server emits valid padding signal, then we've found the intermediate bit
				if( true == server_decrypt_CBC_leak_padding(cipher_info) ){
					intermediate[curr_bit] = hacked_cipher[curr_bit] ^ pkcs7_pad_value;

					output[offset + curr_bit] = (intermediate[curr_bit] ^ orig_hacked_cipher[curr_bit]);
				}
			}

			pkcs7_pad_value++;
		}
	}

	return output;

}

bool server_decrypt_CBC_leak_padding(BlockCipher::CipherData info){
	Xstr decrypted = BlockCipher::decrypt(CBC_ENCRYPT, info);

	if(decrypted.find_padding_type() == Xstr::PaddingType::PKCS7_PADDING){
		return true;
	}
	else{
		return false;
	}
}


/* Challenge 19 */
Xstr break_fixed_nonce_CTR_by_substituting(vector<Xstr> input){
	// make keystream holder
	// we don't know max length of cipher right now but we will
	Xstr keystream;
	keystream.fill(250, 0);

	int max_cipher_size = 0;

	list<int> space_elements;

	for(auto outer_cipher : input){
		if(outer_cipher.size() > max_cipher_size){
			max_cipher_size = outer_cipher.size();
		}

		// Initialize vector with all elements
		space_elements.clear();
		for(int i = 0; i < outer_cipher.size(); i++){
			space_elements.push_back(i);
		}

		// do analysis on ciphers, search one byte at a time
		for(auto inner_cipher : input){
			// results in a cipher same length as shortest input cipher
			Xstr combined = inner_cipher ^ outer_cipher;

			for(int i = 0; i < combined.size(); i++){
				if( !is_english_character(combined[i]) and
					!contains_space_xor_with_special(combined[i]) )
				{
					space_elements.remove(i);
				}
			}
		}

		// using info gleaned from this cipher, partially reconstruct keystream
		for(int space_pos: space_elements){
			keystream[space_pos] = outer_cipher[space_pos] ^ ' ';
		}
	}

	keystream.resize(max_cipher_size);

	return keystream;
}

/* Challenge 20 */

vector<Xstr> break_fixed_nonce_CTR_statistically(vector<Xstr> input){
	// find smallest cipher
	int minsize = 1000000;
	int keysize = AES::BLOCKSIZE; // ??????????????

	for(Xstr cipher: input){
		if(cipher.size() < minsize)
			minsize = cipher.size();
	}

	// truncate ciphertexts to length of smallest cipher
	Xstr encoded = Xstr(input.size() * minsize, 0);

	for(Xstr cipher: input){
		cipher.resize(minsize);
		encoded += cipher;
	}

	/* solve ciphers using same method as repeating-key-xor */

	// TODO: make a function for the following, and reuse it in exercise 6
	int tposed_block_size = encoded.size() / keysize; // round down
	Xstr tposed_block = Xstr(encoded.size(), 0);

	// make transposed block of size keysize by picking out every n'th element (n = key_chr)
	for(int i = 0; i < encoded.size(); i++){
		int row = i % keysize;
		int line = i / keysize;

		tposed_block[(row * tposed_block_size) + line] = encoded[i];
	}

	Xstr key = Xstr();

	for(int blk = 0; blk < encoded.size() / tposed_block_size; blk++){
		cout << blk <<  " " << encoded.size() / tposed_block_size << endl;

		// find single-byte key that best solves according to histogram.
		cout << tposed_block.get_single_block(blk).size() << endl;

		decoded_message repeating_byte_key = solve_single_byte_xor(tposed_block.get_single_block(blk));

		key += repeating_byte_key.key[0];
	}

	cout << key << endl;

//	for(int i = 0; i < encoded.size(); i++){
//		int row = i % tposed_block_size;
//		int line = i / tposed_block_size;
//
//		tposed_block[(row * tposed_block_size) + line] = decoded[i];
//	}
//
//	cout << "= " << tposed_block << endl;
//
//	// decode message according to key and score it based on english characters
//	Xstr decoded_message = input[0].XOR_wraparound(repeating_byte_key.key);
//
//	cout << decoded_message << endl;
}

/* Challenge 25 */
Xstr server_API_cipher_edit(EncryptType e, Xstr cipher, int offset, Xstr newtext){
	static Xstr key = generate_random_AES_key();
	static Xstr nonce = generate_random_nonce(AES::CTR_NONCE_SIZE);

	return BlockCipher::edit_ciphertext(e, cipher, key, nonce, offset, newtext);
}






/*
 * BLOCK CIPHER
 */

// Set AES as default for func pointers
CipherType BlockCipher::cipher_mode = CipherType::AES;
Xstr (* BlockCipher::cipher_encode)(Xstr, Xstr) = AES::encrypt;
Xstr (* BlockCipher::cipher_decode)(Xstr, Xstr) = AES::decrypt;


Xstr BlockCipher::encrypt(EncryptType e, Xstr message, Xstr key, Xstr IV_nonce /* = CR_str() */ ){
	switch(e){
		case ECB_ENCRYPT:
			if( !IV_nonce.empty() ){
				cout << "BlockEncrypt::encrypt(): IV provided for ECB encryption, ignoring." << endl;
			}

			return ECB_encrypt(message, key);
			break;

		case CBC_ENCRYPT:
			if( IV_nonce.empty() ){
				cout << "BlockEncrypt::encrypt(): no IV provided for CBC encryption, "
						"setting equal to 0." << endl;
			}

			return CBC_encrypt(message, key, IV_nonce);
			break;

		case CTR_ENCRYPT:
			if( IV_nonce.empty() ){
				cout << "BlockEncrypt::encrypt(): no nonce provided for CTR encryption, "
						"setting equal to 0." << endl;
			}

			return CTR_encrypt(message, key, IV_nonce);
			break;

		case MT19937_ENCRYPT:
			if( !IV_nonce.empty() ){
				cout << "BlockEncrypt::encrypt(): IV provided for MT19937 encryption, ignoring." << endl;
			}

			return MT19937_encrypt(message, key);
			break;

		default:
			cout << "BlockCipher::encrypt(): ERROR: Encryption type not recognized." << endl;

			return Xstr();
			break;
	}
}

Xstr BlockCipher::decrypt(EncryptType e, Xstr message, Xstr key, Xstr IV_nonce){
	switch(e){
		case ECB_ENCRYPT:
			if( !IV_nonce.empty() ){
				cout << "BlockEncrypt::decrypt(): IV provided for ECB decryption, ignoring." << endl;
			}

			return ECB_decrypt(message, key);
			break;

		case CBC_ENCRYPT:
			if( IV_nonce.empty() ){
				cout << "BlockEncrypt::decrypt(): no IV provided for CBC encryption, "
						"setting equal to 0." << endl;
			}

			return CBC_decrypt(message, key, IV_nonce);
			break;

		case CTR_ENCRYPT:
			if( IV_nonce.empty() ){
				cout << "BlockEncrypt::decrypt(): no nonce provided for CTR encryption, "
						"setting equal to 0." << endl;
			}

			return CTR_decrypt(message, key, IV_nonce);
			break;

		case MT19937_ENCRYPT:
			if( !IV_nonce.empty() ){
				cout << "BlockEncrypt::decrypt(): IV provided for MT19937 decryption, ignoring." << endl;
			}

			return MT19937_decrypt(message, key);
			break;

		default:
			cout << "BlockCipher::decrypt(): ERROR: Encryption type not recognized." << endl;

			return Xstr();
			break;
		}
}

Xstr BlockCipher::encrypt(EncryptType e, CipherData info){
	return encrypt(e, info.message, info.key, info.IV_nonce);
}

Xstr BlockCipher::decrypt(EncryptType e, CipherData info){
	return decrypt(e, info.message, info.key, info.IV_nonce);
}


Xstr BlockCipher::edit_ciphertext(EncryptType e, Xstr cipher, Xstr key, Xstr nonce, int offset, Xstr newtext){
	Xstr decoded = BlockCipher::decrypt(e, cipher, key, nonce);
	Xstr edited = decoded.embed_string(newtext, offset, offset);
	Xstr encoded = BlockCipher::encrypt(e, edited, key, nonce);

	return encoded;
}


void BlockCipher::set_AES_mode(){
	BlockCipher::cipher_mode = CipherType::AES;
	cipher_encode = AES::encrypt;
	cipher_decode = AES::decrypt;
}

void BlockCipher::set_DES_mode(){
	BlockCipher::cipher_mode = CipherType::DES;
	cipher_encode = DES::encrypt;
	cipher_decode = DES::decrypt;
}

Xstr BlockCipher::ECB_encrypt(Xstr message, Xstr key){
	if(key.size() != AES::BLOCKSIZE){
		cout << "ECB_AES_encrypt(): input key is not 16 bytes long." << endl;

		return string();
	}

	int num_ciphers = message.size() / AES::BLOCKSIZE;

	// if message isn't completely divisible into 16 byte chunks,
	// last chunk must be padded - add another ciphertext
	bool pad_last = false;

	if((message.size() % AES::BLOCKSIZE) != 0){
		num_ciphers++;
		pad_last = true;
	}

	// make cipher holder same size as message, fill with 0's
	Xstr ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		Xstr plaintext = Xstr();

		// only execute if we are on the last block, which needs to be padded
		if(pad_last and cipher == (num_ciphers - 1)){
			// grab substring that is at last starting position - cipher * 16
			// it is of length - message.size() % 16
			plaintext = message.substr(cipher * AES::BLOCKSIZE, message.size() % AES::BLOCKSIZE);

			// pad to 16 bytes
			// NOTE: this used to be PKCS7 padding but exercise 14 was hanging up
			plaintext = plaintext.add_padding(Xstr::ZERO_PADDING, AES::BLOCKSIZE);
		}
		// only execute if we are on blocks with a guaranteed 16 bytes
		else{
			plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
		}

		Xstr encrypted = cipher_encode(plaintext, key);

		// copy newly encrypted ciphertext into it's home
		ciphertext = ciphertext.embed_string(encrypted, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return ciphertext;
}

Xstr BlockCipher::ECB_decrypt(Xstr message, Xstr key){
	if((message.size() % AES::BLOCKSIZE) != 0){
		cout << "ECB_AES_decrypt(): input encrypted message is not divisible by 16." << endl;

		return string();
	}
	else if(key.size() != AES::BLOCKSIZE){
		cout << "ECB_AES_decrypt(): input key is not 16 bytes long." << endl;

		return string();
	}

	int num_ciphers = message.size() / AES::BLOCKSIZE;

	// make cipher holder same size as message, fill with 0's
	Xstr plaintext = string();
	plaintext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = num_ciphers - 1; cipher >= 0; cipher--){
		Xstr ciphertext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		Xstr decrypted = cipher_decode(ciphertext, key);

		// copy newly encrypted plaintext into it's home
		plaintext = plaintext.embed_string(decrypted, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	// remove any padding
	plaintext = plaintext.remove_padding(Xstr::PKCS7_PADDING);

	return plaintext;
}

Xstr BlockCipher::CBC_encrypt(Xstr message, Xstr key, Xstr IV){
	if(key.size() != AES::BLOCKSIZE){
		cout << "CBC_AES_encrypt(): input key is not 16 bytes long." << endl;

		return string();
	}
	else if(IV.size() != AES::BLOCKSIZE){
		cout << "CBC_AES_encrypt(): input IV is not 16 bytes long." << endl;

		return string();
	}

	int num_ciphers = message.size() / AES::BLOCKSIZE;

	// if message isn't completely divisible into 16 byte chunks,
	// last chunk must be padded - add another ciphertext
	bool pad_last = false;

	if((message.size() % AES::BLOCKSIZE) != 0){
		num_ciphers++;
		pad_last = true;
	}

	// cipher text that tracks the last ciphertext produced by the ECB function
	// at first set it to IV since the IV is XOR'd with the plaintext intially
	Xstr last_ciphertext = IV;

	// make cipher holder same size as message, fill with 0's
	Xstr ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		Xstr plaintext = string();

		// only execute if we are on the last block, which needs to be padded
		if(pad_last and cipher == (num_ciphers - 1)){
			// grab substring that is at last starting position - cipher * 16
			// it is of length - message.size() % 16
			plaintext = message.substr(cipher * AES::BLOCKSIZE, message.size() % AES::BLOCKSIZE);

			// pad to 16 bytes
			plaintext = plaintext.add_padding(Xstr::PKCS7_PADDING, AES::BLOCKSIZE);
		}
		// only execute if we are on blocks with a guaranteed 16 bytes
		else{
			plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
		}

		Xstr holder = plaintext.XOR( last_ciphertext );

		holder = cipher_encode(holder, key);

		last_ciphertext = holder;

		// copy newly encrypted ciphertext into it's home
		ciphertext = ciphertext.embed_string(holder, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return ciphertext;
}

Xstr BlockCipher::CBC_decrypt(Xstr message, Xstr key, Xstr IV){
	if((message.size() % AES::BLOCKSIZE) != 0){
		cout << "CBC_AES_decrypt(): input encrypted message or key is not divisible by 16." << endl;

		return string();
	}
	if(key.size() != AES::BLOCKSIZE){
		cout << "CBC_AES_decrypt(): input key is not 16 bytes long." << endl;

		return string();
	}
	else if(IV.size() != AES::BLOCKSIZE){
		cout << "CBC_AES_decrypt(): input IV is not 16 bytes long." << endl;

		return string();
	}

	int num_ciphers = message.size() / AES::BLOCKSIZE;

	// the ciphertext - make it equal to the very last cipher text
	Xstr next_ciphertext = message.substr((num_ciphers - 1) * AES::BLOCKSIZE, AES::BLOCKSIZE);

	// make cipher holder same size as message, fill with 0's
	Xstr ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	// make holder for output plaintext
	Xstr plaintext;
	plaintext.resize(message.size(), 0);

	for(int cipher = num_ciphers - 1; cipher >= 0; cipher--){
		ciphertext = next_ciphertext;

		// if we are on the last round,
		// the ciphertext we XOR the input with is the IV
		// also can't let (cipher - 1) & 16 go below 0
		if(cipher == 0){
			next_ciphertext = IV;
		}
		else{
			next_ciphertext = message.substr((cipher - 1) * AES::BLOCKSIZE, AES::BLOCKSIZE);
		}

		Xstr holder = cipher_decode(ciphertext, key);
		holder = holder ^ next_ciphertext ;

		// copy newly decrypted ciphertext into it's home
		plaintext = plaintext.embed_string(holder, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return plaintext;
}


// this implementation accepts nonces up to 16 bytes. Nonces under 16 bytes are zero
// padded to 16 bytes. The nonce value is then incremented by 1 each round.
Xstr BlockCipher::CTR_encrypt(Xstr message, Xstr key, Xstr nonce){
	if(key.size() != AES::BLOCKSIZE){
		cout << "CTR_AES_encrypt(): input key is not 16 bytes long." << endl;

		return string();
	}
	else if(nonce.size() > AES::CTR_NONCE_SIZE){
		cout << "CTR_AES_encrypt(): input nonce size is greater than 16 bytes." << endl;

		return string();
	}
	// if nonce isn't quite 16 bytes, then pad with zeros up to 16
	else if(nonce.size() < AES::CTR_NONCE_SIZE){
		nonce = nonce.add_padding( Xstr::ZERO_PADDING, AES::CTR_COUNTER_SIZE );
	}

	// if message isn't completely divisible into 16 byte chunks,
	// last chunk is not padded since this is CTR mode
	// The last, uneven size chunk is merely XOR'd against the
	// corresponding subsection of the keystream
	int num_ciphers = ceil((float) message.size() / (float) AES::BLOCKSIZE);


	Xstr ciphertext = Xstr();
	Xstr cipher_input;
	Xstr counter;
	counter.fill(AES::CTR_COUNTER_SIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		Xstr plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		cipher_input = nonce.little_endian() + counter.little_endian();
		Xstr encrypted_nonce = cipher_encode(cipher_input, key);

		// TODO: IDEA: instead of copying blocks over, just use container as accumulator that gets XOR'd

		// add new ciphertext by XORing with encrypted nonce
		ciphertext += encrypted_nonce ^ plaintext;

		// add 1 to the integer represented by the string
		counter.increment();
	}

	return ciphertext;
}

// TODO: need to make AES::BLOCKSIE and others more general
// TODO: put these checks in their own encapsulated checking functions

Xstr BlockCipher::CTR_decrypt(Xstr message, Xstr key, Xstr nonce){
	if(key.size() != AES::BLOCKSIZE){
		cout << "CTR_AES_decrypt(): input key is not 16 bytes long." << endl;

		return string();
	}
	else if(nonce.size() > AES::CTR_NONCE_SIZE){
		cout << "CTR_AES_decrypt(): input nonce size is greater than 16 bytes." << endl;

		return string();
	}
	// if nonce isn't quite 16 bytes, then pad with zeros up to 16
	else if(nonce.size() < AES::CTR_NONCE_SIZE){
		nonce = nonce.add_padding( Xstr::ZERO_PADDING, AES::CTR_COUNTER_SIZE );
	}

	// if message isn't completely divisible into 16 byte chunks,
	// last chunk is not padded since this is CTR mode
	// The last, uneven size chunk is merely XOR'd against the
	// corresponding subsection of the keystream
	int num_ciphers = ceil((float) message.size() / (float) AES::BLOCKSIZE);

	Xstr plaintext = Xstr();

	Xstr cipher_input;
	Xstr counter;
	counter.fill(AES::CTR_COUNTER_SIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		Xstr ciphertext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		cipher_input = nonce.little_endian() + counter.little_endian();

		// TODO: IDEA: instead of copying blocks over, just use container as accumulator that gets XOR'd

		Xstr encrypted_nonce = cipher_encode(cipher_input, key);

		// add new plaintext by XORing with encrypted nonce
		plaintext += encrypted_nonce ^ ciphertext;

		// add 1 to the integer represented by the string
		counter.increment();
	}

	return plaintext;
}

/* Challenge 24 */

Xstr BlockCipher::gen_MT19937_keystream(Xstr key, int stream_size){
	MersenneTwister mt(key.as_decimal(), MT::_64BIT);
	Xstr keystream = Xstr(stream_size, 0);

	// put keystream gen into separate function
	for(int i = 0; i < stream_size; i++){
		uint8_t new_byte = (uint8_t) mt.rand_mt(1); // want 8-bit output for sequence

		keystream[i] = new_byte;
	}

	return keystream;
}

// The encrypt and decrypt for MT19937 are identical (just like for CTR)
// need only implement once
Xstr BlockCipher::MT19937_encrypt(Xstr decrypted, Xstr key){
	if(key.size() != 2){ // key must be 16 bit
		cout << "BlockCipher::MT19937_encrypt(): input key is not 16 bits long." << endl;

		return Xstr();
	}

	Xstr keystream = gen_MT19937_keystream(key, decrypted.size());

	Xstr encrypted = decrypted ^ keystream;

	return encrypted;
}

Xstr BlockCipher::MT19937_decrypt(Xstr encrypted, Xstr key){
	if(key.size() != 2){ // key must be 16 bit
		cout << "BlockCipher::MT19937_decrypt(): input key is not 16 bits long." << endl;

		return Xstr();
	}
	else{
		return MT19937_encrypt(encrypted, key);
	}
}
