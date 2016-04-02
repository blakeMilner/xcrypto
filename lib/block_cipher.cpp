#include "block_cipher.hpp"


int generate_rand_num_between(int lbound, int ubound){
	return (rand() % (ubound - lbound)) + lbound;
}

XStr generate_random_ascii_string(int num_bytes){
	// seed the rand() function with the current time.
	srand(time(NULL));

	XStr rand_s;
	rand_s.resize(num_bytes, 0);

	// fill each byte of the key up with random numbers
	for(int i = 0; i < num_bytes; i++){
		rand_s[i] = (uint8_t) generate_rand_num_between(0, 256);
	}

	return rand_s;
}

XStr generate_random_AES_IV(int len){
	return generate_random_ascii_string(len);
}

XStr generate_random_AES_key(int len){
	return generate_random_ascii_string(len);
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
XStr AES::rjindael_mix_column(XStr r) {
 	// make sure input CR_str is 16 bytes
	if(r.size() != 4){
		cout << "rjindael_mix_columns: input column size is not 4 bytes." << endl;

		return XStr();
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
XStr AES::rjindael_unmix_column(XStr r) {
	 	// make sure input CR_str is 16 bytes
		if(r.size() != 4){
			cout << "rjindael_mix_columns: input column size is not 4 bytes." << endl;

			return XStr();
		}

        // make output CR_str
        XStr o = XStr();
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

XStr AES::substitute_bytes(XStr input){
	// apply nonlinear byte substitution
	// extract first and second digit and use it in LUT
	for(int i = 0; i < AES::BLOCKSIZE; i++){
		input[i] = rjindael_sbox_lookup( input[i] );
	}

	return input;
}

XStr AES::unsubstitute_bytes(XStr input){
	// apply nonlinear byte substitution
	// extract first and second digit and use it in LUT
	for(int i = 0; i < AES::BLOCKSIZE; i++){
		input[i] = inv_rjindael_sbox_lookup( input[i] );
	}

	return input;
}

XStr AES::mix_columns(XStr input){
	XStr input_column = XStr();
    input_column.resize(4, 0);

	// combine the 4 bytes in each column into a new 4-byte column using
	// an invertible linear transformation.
    for(int col = 0; col < 4; col++){
    	// copy column to contiguous
    	for(int row = 0; row < 4; row++){
    		input_column[row] = input[(col * 4) + row];
    	}

    	// mix column according to rjindael algorithm
    	XStr mixed_column = rjindael_mix_column(input_column);

    	// copy mixed column back to original location
    	for(int row = 0; row < 4; row++){
    		input[(col * 4) + row] = mixed_column[row];
    	}
    }

    return input;
}

XStr AES::unmix_columns(XStr input){
	XStr mixed_column = XStr();
    mixed_column.resize(4, 0);

	// combine the 4 bytes in each column into a new 4-byte column using
	// an invertible linear transformation.
    for(int col = 3; col >= 0; col--){
    	// copy mixed column back to original location
    	for(int row = 3; row >= 0; row--){
    		mixed_column[row] = input[(col * 4) + row];
    	}

    	// mix column according to rjindael algorithm
    	XStr input_column = rjindael_unmix_column(mixed_column);

    	// copy column to contiguous
    	for(int row = 3; row >= 0; row--){
    		input[(col * 4) + row] = input_column[row];
    	}
    }

    return input;
}

XStr AES::shift_rows(XStr input){
	XStr output = XStr();
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

XStr AES::unshift_rows(XStr input){
	XStr output = XStr();
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

	string all_keys = string();
	all_keys.resize(176, 0);

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
XStr AES::add_round_key(XStr plaintext, const vector<string>& key, int round){
	if(plaintext.size() != AES::BLOCKSIZE){
		cout << "rjindael_appl_round_key(): message size is not 16 bytes!" << endl;

		return string();
	}

	// xor the input text with the key for the corresponding round
	XStr ciphertext = plaintext ^ key[round];

	return ciphertext;
}

// based on the Rjindael algorithm
XStr AES::encrypt(XStr plaintext, XStr key){
	if(plaintext.size() < AES::BLOCKSIZE){
		plaintext = plaintext.add_padding(XStr::PKCS7_PADDING, AES::BLOCKSIZE);
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
	XStr ciphertext = plaintext.as_ascii();
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
XStr AES::decrypt(XStr ciphertext, XStr key){
	if(ciphertext.size() < AES::BLOCKSIZE){
		ciphertext = ciphertext.add_padding(XStr::PKCS7_PADDING, AES::BLOCKSIZE);
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
	XStr plaintext = ciphertext;

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
XStr DES::encrypt(XStr plaintext, XStr key){
	return XStr();
}

XStr DES::decrypt(XStr ciphertext, XStr key){
	return XStr();
}

bool detect_ECB_AES_encryption(XStr message){
    int blocks_count = message.size() / AES::BLOCKSIZE;
    int matches = 0;

    set<XStr> all_blocks;

    // add all of the ciphertext blocks within the message into a set
    for (int index = 0; index < blocks_count; index++){
		XStr block = message.substr(index * AES::BLOCKSIZE, AES::BLOCKSIZE);

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

XStr encrypt_using_CBC_or_ECB(XStr message){
	int num_rand_prefix_bytes = generate_rand_num_between(5, 10);
	int num_rand_suffix_bytes = generate_rand_num_between(5, 10);

	XStr prefix_string = generate_random_ascii_string(num_rand_prefix_bytes);
	XStr suffix_string = generate_random_ascii_string(num_rand_suffix_bytes);

	XStr appended_message = prefix_string + message + suffix_string;
	appended_message = appended_message.add_padding(XStr::PKCS7_PADDING, AES::BLOCKSIZE); // pad appended message up to even block size

	XStr rand_key = generate_random_AES_key(AES::BLOCKSIZE);

	bool encrypt_using_ECB = rand() % 2;

	if(encrypt_using_ECB){
		return BlockCipher::encrypt(ECB_ENCRYPT, appended_message, rand_key);
	}
	else{
		XStr rand_IV = generate_random_AES_IV(AES::BLOCKSIZE);

		return BlockCipher::encrypt(CBC_ENCRYPT, appended_message, rand_key, rand_IV);
	}
}






///////// next: make an attribute for CR_str that tells what kind of encryption it has
////////// when detect ECB_CBC is used, it sets this attribute


// accepts a function pointer that implements an arbitrary encryption fucntion
// inputs - message to be encrypted
// outputs - encrypted message
EncryptType detect_ECB_or_CBC_encryption(XStr (*encryption_fnc)(XStr message)){
	// no matter what gets prepended/appended, 2nd and 3rd block will be all 0's
	// because of size = 48
	XStr message = XStr();
	message.resize(48, 0);

	XStr encrypted_message = encryption_fnc(message);

	if(encrypted_message.get_single_block(1, AES::BLOCKSIZE) == encrypted_message.get_single_block(2, AES::BLOCKSIZE)){
//		cout << "ECB" << endl;
		return EncryptType::ECB_ENCRYPT;
	}
	else{
//		cout << "CBC" << endl;
		return EncryptType::CBC_ENCRYPT;
	}
}

XStr append_unknown_string_and_encrypt_ECB(XStr message){
	// generate unknown key only once
	static XStr random_key = generate_random_AES_key(AES::BLOCKSIZE);
	// create unknown string once
	static XStr unknown_string = XStr("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
												"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
												"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
												"YnkK", XStr::BASE64_ENCODED);

	return BlockCipher::encrypt(ECB_ENCRYPT, message + unknown_string, random_key);
}

XStr byte_at_a_time_ECB_decrypt_simple(){
	XStr (*blackbox)(XStr);
	blackbox = append_unknown_string_and_encrypt_ECB;

	/* First, find the block size of the cipher by feeding in successive test characters */
	XStr known_string = XStr("A");
	XStr new_cipher = blackbox(known_string);
	int block_size = 0;
	int last_size = 0;
	XStr unknown_str_new_block = XStr();

	/* find unknown string size by feeding in empty string */
	int unknown_string_size = blackbox( XStr() ).size();
	int unknown_string_blocks = ceil(unknown_string_size / AES::BLOCKSIZE);

	do{
		last_size = new_cipher.size();
		known_string += XStr("A");
		new_cipher = blackbox(known_string);
		block_size++;
	}
	while(new_cipher.size() == last_size);

	/* Verify that the function is using ECB */
	if(EncryptType::ECB_ENCRYPT != detect_ECB_or_CBC_encryption(blackbox)){
		cout << "byte_at_a_time_ECB_decrypt_simple(): function is not using ECB encryption." << endl;

		return XStr();
	}

	/* Solve each block consecutively, solving one byte at a time */
	XStr previous_blocks = XStr();
	for(int blk = 0; blk < unknown_string_blocks; blk++){
		unknown_str_new_block = XStr();
		
		for(int byte = AES::BLOCKSIZE - 1; byte >= 0; byte--){
			// make partial string with dummy chars (A's)
			known_string = string(byte, 'A');

			// encrypt once using partial string
			XStr encrypted_actual = blackbox(known_string);

			// add known bytes to end of test string - do this after we compute encrypted message we compare test cases to
			known_string += previous_blocks;

			// add different byte values to end of known_string, see if this matches known_string with no extra byte
			XStr known_string_guess;
			XStr prefix = known_string + unknown_str_new_block;
			
			for(char c = 0; c < 256; c++){
				known_string_guess = prefix + string(1, c); // add new guess character to end of string

				// encrypt our new guess
				XStr encrypted_guess = blackbox(known_string_guess);

				// if the actual and guessed blocks match, then we've found the next byte of unkown_string
				if(encrypted_actual.get_single_block(blk, AES::BLOCKSIZE) == encrypted_guess.get_single_block(blk, AES::BLOCKSIZE)){
					unknown_str_new_block += c;
					break;
				}
			}
		}

		previous_blocks += unknown_str_new_block;
	}

	return previous_blocks;
}

// TODO: there is no prefix being added here!
XStr append_unknown_string_random_prefix_and_encrypt_ECB(XStr message){
	// generate unknown key only once
	static XStr random_key = generate_random_AES_key(AES::BLOCKSIZE);
	// create unknown string once
	static XStr unknown_string = XStr("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
												"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
												"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
												"YnkK", XStr::BASE64_ENCODED);

	return BlockCipher::encrypt(ECB_ENCRYPT, message + unknown_string, random_key);
}

XStr byte_at_a_time_ECB_decrypt_hard(){
	XStr (*blackbox)(XStr);
	blackbox = append_unknown_string_random_prefix_and_encrypt_ECB;

	/* First, find the block size of the cipher by feeding in successive test characters */
	XStr known_string = XStr("A");
	XStr new_cipher = blackbox(known_string);
	int block_size = 0;
	int last_size = 0;
	XStr unknown_str_new_block = XStr();

	/* find unknown string size by feeding in empty string */
	int unknown_string_size = blackbox( XStr() ).size();
	int unknown_string_blocks = unknown_string_size / AES::BLOCKSIZE;

	// find block size
	do{
		last_size = new_cipher.size();
		known_string += XStr("A");
		new_cipher = blackbox(known_string);
		block_size++;
	}
	while(new_cipher.size() == last_size);

	/* Verify that the function is using ECB */
	if(EncryptType::ECB_ENCRYPT != detect_ECB_or_CBC_encryption(blackbox)){
		cout << "byte_at_a_time_ECB_decrypt_simple(): function is not using ECB encryption." << endl;

		return XStr();
	}

	/* Solve each block consecutively, solving one byte at a time */
	XStr previous_blocks = XStr();
	for(int blk = 0; blk < unknown_string_blocks; blk++){
		unknown_str_new_block = XStr();

		for(int byte = AES::BLOCKSIZE - 1; byte >= 0; byte--){
			// make partial string with dummy chars (A's)
			known_string = string(byte, 'A');

			// encrypt once using partial string
			XStr encrypted_actual = blackbox(known_string);

			// add known bytes to end of test string - do this after we compute encrypted message we compare test cases to
			known_string += previous_blocks;

			// add different byte values to end of known_string, see if this matches known_string with no extra byte
			XStr known_string_guess;
			XStr prefix = known_string + unknown_str_new_block;

			//cout << unknown_str_new_block.as_base64() << " " << endl;

			for(char c = 0; c < 256; c++){
				known_string_guess = prefix + c; // add new guess character to end of string

				// encrypt our new guess
				XStr encrypted_guess = blackbox(known_string_guess);

				// if the actual and guessed blocks match, then we've found the next byte of unkown_string
				if(encrypted_actual.get_single_block(blk, AES::BLOCKSIZE) == encrypted_guess.get_single_block(blk, AES::BLOCKSIZE)){
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

/* BLOCK CIPHER */

// Set AES as default
CipherType BlockCipher::cipher_mode = CipherType::AES;
XStr (* BlockCipher::cipher_encode)(XStr, XStr) = AES::encrypt;
XStr (* BlockCipher::cipher_decode)(XStr, XStr) = AES::decrypt;


XStr BlockCipher::encrypt(EncryptType e, XStr message, XStr key, XStr IV_nonce /* = CR_str() */ ){
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
		}
}

XStr BlockCipher::decrypt(EncryptType e, XStr message, XStr key, XStr IV_nonce){
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
		}
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

XStr BlockCipher::ECB_encrypt(XStr message, XStr key){
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
	XStr ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		XStr plaintext = XStr();

		// only execute if we are on the last block, which needs to be padded
		if(pad_last and cipher == (num_ciphers - 1)){
			// grab substring that is at last starting position - cipher * 16
			// it is of length - message.size() % 16
			plaintext = message.substr(cipher * AES::BLOCKSIZE, message.size() % AES::BLOCKSIZE);

			// pad to 16 bytes
			// NOTE: this used to be PKCS7 padding but exercise 14 was hanging up
			plaintext = plaintext.add_padding(XStr::ZERO_PADDING, AES::BLOCKSIZE);
		}
		// only execute if we are on blocks with a guaranteed 16 bytes
		else{
			plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
		}

		XStr encrypted = cipher_encode(plaintext, key);

		// copy newly encrypted ciphertext into it's home
		ciphertext = ciphertext.embed_string(encrypted, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return ciphertext;
}

XStr BlockCipher::ECB_decrypt(XStr message, XStr key){
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
	XStr plaintext = string();
	plaintext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = num_ciphers - 1; cipher >= 0; cipher--){
		XStr ciphertext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		XStr decrypted = cipher_decode(ciphertext, key);

		// copy newly encrypted plaintext into it's home
		plaintext = plaintext.embed_string(decrypted, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	// remove any padding
	plaintext = plaintext.remove_padding(XStr::PKCS7_PADDING);

	return plaintext;
}

XStr BlockCipher::CBC_encrypt(XStr message, XStr key, XStr IV){
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
	XStr last_ciphertext = IV;

	// make cipher holder same size as message, fill with 0's
	XStr ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		XStr plaintext = string();

		// only execute if we are on the last block, which needs to be padded
		if(pad_last and cipher == (num_ciphers - 1)){
			// grab substring that is at last starting position - cipher * 16
			// it is of length - message.size() % 16
			plaintext = message.substr(cipher * AES::BLOCKSIZE, message.size() % AES::BLOCKSIZE);

			// pad to 16 bytes
			plaintext = plaintext.add_padding(XStr::PKCS7_PADDING, AES::BLOCKSIZE);
		}
		// only execute if we are on blocks with a guaranteed 16 bytes
		else{
			plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
		}

		XStr holder = plaintext.XOR( last_ciphertext );
		holder = cipher_encode(holder, key);

		last_ciphertext = holder;

		// copy newly encrypted ciphertext into it's home
		ciphertext = ciphertext.embed_string(holder, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return ciphertext;
}

XStr BlockCipher::CBC_decrypt(XStr message, XStr key, XStr IV){
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
	XStr next_ciphertext = message.substr((num_ciphers - 1) * AES::BLOCKSIZE, AES::BLOCKSIZE);

	// make cipher holder same size as message, fill with 0's
	XStr ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	// make holder for output plaintext
	XStr plaintext;
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

		XStr holder = cipher_decode(ciphertext, key);
		holder = holder ^ next_ciphertext ;

		// copy newly decrypted ciphertext into it's home
		plaintext = plaintext.embed_string(holder, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return plaintext;
}


// this implementation accepts nonces up to 16 bytes. Nonces under 16 bytes are zero
// padded to 16 bytes. The nonce value is then incremented by 1 each round.
XStr BlockCipher::CTR_encrypt(XStr message, XStr key, XStr nonce){
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
		nonce = nonce.add_padding( XStr::ZERO_PADDING, AES::CTR_COUNTER_SIZE );
	}

	// if message isn't completely divisible into 16 byte chunks,
	// last chunk is not padded since this is CTR mode
	// The last, uneven size chunk is merely XOR'd against the
	// corresponding subsection of the keystream
	int num_ciphers = ceil((float) message.size() / (float) AES::BLOCKSIZE);


	XStr ciphertext = XStr();
	XStr cipher_input;
	XStr counter;
	counter.fill(AES::CTR_COUNTER_SIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		XStr plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		cipher_input = nonce.little_endian() + counter.little_endian();
		XStr encrypted_nonce = cipher_encode(cipher_input, key);

		// TODO: IDEA: instead of copying blocks over, just use container as accumulator that gets XOR'd

		// add new ciphertext by XORing with encrypted nonce
		ciphertext += encrypted_nonce ^ plaintext;

		// add 1 to the integer represented by the string
		counter.increment();
	}

	return ciphertext;
}

XStr BlockCipher::CTR_decrypt(XStr message, XStr key, XStr nonce){
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
		nonce = nonce.add_padding( XStr::ZERO_PADDING, AES::CTR_COUNTER_SIZE );
	}

	// if message isn't completely divisible into 16 byte chunks,
	// last chunk is not padded since this is CTR mode
	// The last, uneven size chunk is merely XOR'd against the
	// corresponding subsection of the keystream
	int num_ciphers = ceil((float) message.size() / (float) AES::BLOCKSIZE);

	XStr plaintext = XStr();

	XStr cipher_input;
	XStr counter;
	counter.fill(AES::CTR_COUNTER_SIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		XStr ciphertext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		cipher_input = nonce.little_endian() + counter.little_endian();

		// TODO: IDEA: instead of copying blocks over, just use container as accumulator that gets XOR'd

		XStr encrypted_nonce = cipher_encode(cipher_input, key);

		// add new plaintext by XORing with encrypted nonce
		plaintext += encrypted_nonce ^ ciphertext;

		// add 1 to the integer represented by the string
		counter.increment();
	}

	return plaintext;
}
