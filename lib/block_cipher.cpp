#include "block_cipher.hpp"


// TODO: make class called BlockCipher, holds ECB, CBC, etc.



int generate_rand_num_between(int lbound, int ubound){
	return (rand() % (ubound - lbound)) + lbound;
}

CR_str generate_random_ascii_string(int num_bytes){
	// seed the rand() function with the current time.
	srand(time(NULL));

	CR_str rand_s;
	rand_s.resize(num_bytes, 0);

	// fill each byte of the key up with random numbers
	for(int i = 0; i < num_bytes; i++){
		rand_s[i] = (uint8_t) generate_rand_num_between(0, 256);
	}

	return rand_s;
}

// 16 byte IV
CR_str generate_random_AES_IV(int len){
	return generate_random_ascii_string(len);
}

// 16 byte key
CR_str generate_random_AES_key(int len){
	return generate_random_ascii_string(len);
}

uint8_t rjindael_sbox_lookup(uint8_t input){
	uint8_t digit1 = (input & 0xF0) >> 4;
	uint8_t digit2 = (input & 0x0F)     ;

	input = rijndael_sbox[digit1][digit2];

	return input;
}

uint8_t inv_rjindael_sbox_lookup(uint8_t input){
	uint8_t digit1 = (input & 0xF0) >> 4;
	uint8_t digit2 = (input & 0x0F)     ;

	input = inv_rijndael_sbox[digit1][digit2];

	return input;
}

unsigned char gmul(unsigned char a, unsigned char b) {
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
CR_str rjindael_mix_columns(CR_str r) {
 	// make sure input CR_str is 16 bytes
	if(r.size() != 4){
		cout << "rjindael_mix_columns: input column size is not 4 bytes." << endl;

		return CR_str();
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
CR_str rjindael_unmix_columns(CR_str r) {
	 	// make sure input CR_str is 16 bytes
		if(r.size() != 4){
			cout << "rjindael_mix_columns: input column size is not 4 bytes." << endl;

			return CR_str();
		}

        // make output CR_str
        CR_str o = CR_str();
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

CR_str substitute_bytes(CR_str input){
	// apply nonlinear byte substitution
	// extract first and second digit and use it in LUT
	for(int i = 0; i < AES::BLOCKSIZE; i++){
		input[i] = rjindael_sbox_lookup( input[i] );
	}

	return input;
}

CR_str unsubstitute_bytes(CR_str input){
	// apply nonlinear byte substitution
	// extract first and second digit and use it in LUT
	for(int i = 0; i < AES::BLOCKSIZE; i++){
		input[i] = inv_rjindael_sbox_lookup( input[i] );
	}

	return input;
}

CR_str mix_columns(CR_str input){
	CR_str input_column = CR_str();
    input_column.resize(4, 0);

	// combine the 4 bytes in each column into a new 4-byte column using
	// an invertible linear transformation.
    for(int col = 0; col < 4; col++){
    	// copy column to contiguous
    	for(int row = 0; row < 4; row++){
    		input_column[row] = input[(col * 4) + row];
    	}

    	// mix column according to rjindael algorithm
    	CR_str mixed_column = rjindael_mix_columns(input_column);

    	// copy mixed column back to original location
    	for(int row = 0; row < 4; row++){
    		input[(col * 4) + row] = mixed_column[row];
    	}
    }

    return input;
}

CR_str unmix_columns(CR_str input){
	CR_str mixed_column = CR_str();
    mixed_column.resize(4, 0);

	// combine the 4 bytes in each column into a new 4-byte column using
	// an invertible linear transformation.
    for(int col = 3; col >= 0; col--){
    	// copy mixed column back to original location
    	for(int row = 3; row >= 0; row--){
    		mixed_column[row] = input[(col * 4) + row];
    	}

    	// mix column according to rjindael algorithm
    	CR_str input_column = rjindael_unmix_columns(mixed_column);

    	// copy column to contiguous
    	for(int row = 3; row >= 0; row--){
    		input[(col * 4) + row] = input_column[row];
    	}
    }

    return input;
}

CR_str shift_rows(CR_str input){
	CR_str output = CR_str();
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

CR_str unshift_rows(CR_str input){
	CR_str output = CR_str();
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
void rotate(unsigned char *in) {
	unsigned char a;
	a = in[0];

	for(unsigned char c = 0; c < 3 ; c++){
		in[c] = in[c + 1];
	}

	in[3] = a;

	return;
}

/* Calculate the rcon used in key expansion */
unsigned char rcon(unsigned char in) {
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
void schedule_core(unsigned char *in, unsigned char i) {
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
vector<string> expand_key(unsigned char *input) {
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
CR_str rjindael_appl_round_key(CR_str plaintext, const vector<string>& key, int round){
	if(plaintext.size() != AES::BLOCKSIZE){
		cout << "rjindael_appl_round_key(): message size is not 16 bytes!" << endl;

		return string();
	}

	// xor the input text with the key for the corresponding round
	CR_str ciphertext = plaintext ^ key[round];

	return ciphertext;
}

// based on the Rjindael algorithm
CR_str AES_cipher_encrypt(CR_str plaintext, CR_str key){
	if(plaintext.size() < AES::BLOCKSIZE){
		plaintext = plaintext.add_padding(CR_str::PKCS7_PADDING, AES::BLOCKSIZE);
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
	CR_str ciphertext = plaintext.as_ascii();
    // initially XOR the input text with the key
    ciphertext = rjindael_appl_round_key( ciphertext, round_keys, 0 );

	for(int round = 1; round <= 10; round++){
		ciphertext = substitute_bytes(ciphertext);
		ciphertext = shift_rows(ciphertext);

		// don't mix columns on last round!
		if(round < 10){
			ciphertext = mix_columns(ciphertext);
		}

		ciphertext = rjindael_appl_round_key( ciphertext, round_keys, round );
	}

	return ciphertext;
}

// based on the Rjindael algorithm
CR_str AES_cipher_decrypt(CR_str ciphertext, CR_str key){
	if(ciphertext.size() < AES::BLOCKSIZE){
		ciphertext = ciphertext.add_padding(CR_str::PKCS7_PADDING, AES::BLOCKSIZE);
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
	CR_str plaintext = ciphertext;

    //  go backwards through rounds and keys this time
	// this is merely a reversal of the methods found in the encrypt function
	for(int round = 10; round >= 1; round--){
		plaintext = rjindael_appl_round_key( plaintext, round_keys, round );

		// don't unmix columns on last round encrypting/first round of decrypting!
		if(round < 10){
			plaintext = unmix_columns(plaintext);
		}

		plaintext = unshift_rows(plaintext);
		plaintext = unsubstitute_bytes(plaintext);
	}

    // account for the initial XOR between input message and the master key
    plaintext = rjindael_appl_round_key( plaintext, round_keys, 0 );

	return plaintext;
}

CR_str ECB_AES_encrypt(CR_str message, CR_str key){
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
	CR_str ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		CR_str plaintext = CR_str();

		// only execute if we are on the last block, which needs to be padded
		if(pad_last and cipher == (num_ciphers - 1)){
			// grab substring that is at last starting position - cipher * 16
			// it is of length - message.size() % 16
			plaintext = message.substr(cipher * AES::BLOCKSIZE, message.size() % AES::BLOCKSIZE);

			// pad to 16 bytes
			// NOTE: this used to be PKCS7 padding but exercise 14 was hanging up
			plaintext = plaintext.add_padding(CR_str::ZERO_PADDING, AES::BLOCKSIZE);
		}
		// only execute if we are on blocks with a guaranteed 16 bytes
		else{
			plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
		}

		CR_str encrypted = AES_cipher_encrypt(plaintext, key);

		// copy newly encrypted ciphertext into it's home
		ciphertext = ciphertext.embed_string(encrypted, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return ciphertext;
}

CR_str ECB_AES_decrypt(CR_str message, CR_str key){
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
	CR_str plaintext = string();
	plaintext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = num_ciphers - 1; cipher >= 0; cipher--){
		CR_str ciphertext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		CR_str decrypted = AES_cipher_decrypt(ciphertext, key);

		// copy newly encrypted plaintext into it's home
		plaintext = plaintext.embed_string(decrypted, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	// remove any padding 
	plaintext = plaintext.remove_padding(CR_str::PKCS7_PADDING);
	
	return plaintext;
}

bool detect_ECB_AES_encryption(CR_str message){
    int blocks_count = message.size() / AES::BLOCKSIZE;
    int matches = 0;

    set<CR_str> all_blocks;

    // add all of the ciphertext blocks within the message into a set
    for (int index = 0; index < blocks_count; index++){
		CR_str block = message.substr(index * AES::BLOCKSIZE, AES::BLOCKSIZE);

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

CR_str CBC_AES_encrypt(CR_str message, CR_str key, CR_str IV){
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
	CR_str last_ciphertext = IV;

	// make cipher holder same size as message, fill with 0's
	CR_str ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		CR_str plaintext = string();

		// only execute if we are on the last block, which needs to be padded
		if(pad_last and cipher == (num_ciphers - 1)){
			// grab substring that is at last starting position - cipher * 16
			// it is of length - message.size() % 16
			plaintext = message.substr(cipher * AES::BLOCKSIZE, message.size() % AES::BLOCKSIZE);

			// pad to 16 bytes
			plaintext = plaintext.add_padding(CR_str::PKCS7_PADDING, AES::BLOCKSIZE);
		}
		// only execute if we are on blocks with a guaranteed 16 bytes
		else{
			plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
		}

		CR_str holder = plaintext.XOR( last_ciphertext );
		holder = AES_cipher_encrypt(holder, key);

		last_ciphertext = holder;

		// copy newly encrypted ciphertext into it's home
		ciphertext = ciphertext.embed_string(holder, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return ciphertext;
}

CR_str CBC_AES_decrypt(CR_str message, CR_str key, CR_str IV){
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
	CR_str next_ciphertext = message.substr((num_ciphers - 1) * AES::BLOCKSIZE, AES::BLOCKSIZE);

	// make cipher holder same size as message, fill with 0's
	CR_str ciphertext;
	ciphertext.resize(num_ciphers * AES::BLOCKSIZE, 0);

	// make holder for output plaintext
	CR_str plaintext;
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

		CR_str holder = AES_cipher_decrypt(ciphertext, key);
		holder = holder ^ next_ciphertext ;

		// copy newly decrypted ciphertext into it's home
		plaintext = plaintext.embed_string(holder, cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);
	}

	return plaintext;
}

CR_str encrypt_using_CBC_or_ECB(CR_str message){
	int num_rand_prefix_bytes = generate_rand_num_between(5, 10);
	int num_rand_suffix_bytes = generate_rand_num_between(5, 10);

	CR_str prefix_string = generate_random_ascii_string(num_rand_prefix_bytes);
	CR_str suffix_string = generate_random_ascii_string(num_rand_suffix_bytes);

	CR_str appended_message = prefix_string + message + suffix_string;
	appended_message = appended_message.add_padding(CR_str::PKCS7_PADDING, AES::BLOCKSIZE); // pad appended message up to even block size

	CR_str rand_key = generate_random_AES_key(AES::BLOCKSIZE);

	bool encrypt_using_ECB = rand() % 2;

	if(encrypt_using_ECB){
		return ECB_AES_encrypt(appended_message, rand_key);
	}
	else{
		CR_str rand_IV = generate_random_AES_IV(AES::BLOCKSIZE);

		return CBC_AES_encrypt(appended_message, rand_key, rand_IV);
	}
}






///////// next: make an attribute for CR_str that tells what kind of encryption it has
////////// when detect ECB_CBC is used, it sets this attribute


// accepts a function pointer that implements an arbitrary encryption fucntion
// inputs - message to be encrypted
// outputs - encrypted message
CR_str::EncryptType detect_ECB_or_CBC_encryption(CR_str (*encryption_fnc)(CR_str message)){
	// no matter what gets prepended/appended, 2nd and 3rd block will be all 0's
	// because of size = 48
	CR_str message = CR_str();
	message.resize(48, 0);

	CR_str encrypted_message = encryption_fnc(message);

	if(encrypted_message.get_single_block(1, AES::BLOCKSIZE) == encrypted_message.get_single_block(2, AES::BLOCKSIZE)){
//		cout << "ECB" << endl;
		return CR_str::ECB_ENCRYPTION;
	}
	else{
//		cout << "CBC" << endl;
		return CR_str::CBC_ENCRYPTION;
	}
}

CR_str append_unknown_string_and_encrypt_ECB(CR_str message){
	// generate unknown key only once
	static CR_str random_key = generate_random_AES_key(AES::BLOCKSIZE);
	// create unknown string once
	static CR_str unknown_string = CR_str("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
												"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
												"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
												"YnkK", CR_str::BASE64_ENCODED);

	return ECB_AES_encrypt(message + unknown_string, random_key);
}

CR_str byte_at_a_time_ECB_decrypt_simple(){
	CR_str (*blackbox)(CR_str);
	blackbox = append_unknown_string_and_encrypt_ECB;

	/* First, find the block size of the cipher by feeding in successive test characters */
	CR_str known_string = CR_str("A");
	CR_str new_cipher = blackbox(known_string);
	int block_size = 0;
	int last_size = 0;
	CR_str unknown_str_new_block = CR_str();

	/* find unknown string size by feeding in empty string */
	int unknown_string_size = blackbox( CR_str() ).size();
	int unknown_string_blocks = ceil(unknown_string_size / AES::BLOCKSIZE);

	do{
		last_size = new_cipher.size();
		known_string += CR_str("A");
		new_cipher = blackbox(known_string);
		block_size++;
	}
	while(new_cipher.size() == last_size);

	/* Verify that the function is using ECB */
	if(CR_str::ECB_ENCRYPTION != detect_ECB_or_CBC_encryption(blackbox)){
		cout << "byte_at_a_time_ECB_decrypt_simple(): function is not using ECB encryption." << endl;

		return CR_str();
	}

	/* Solve each block consecutively, solving one byte at a time */
	CR_str previous_blocks = CR_str();
	for(int blk = 0; blk < unknown_string_blocks; blk++){
		unknown_str_new_block = CR_str();
		
		for(int byte = AES::BLOCKSIZE - 1; byte >= 0; byte--){
			// make partial string with dummy chars (A's)
			known_string = string(byte, 'A');

			// encrypt once using partial string
			CR_str encrypted_actual = blackbox(known_string);

			// add known bytes to end of test string - do this after we compute encrypted message we compare test cases to
			known_string += previous_blocks;

			// add different byte values to end of known_string, see if this matches known_string with no extra byte
			CR_str known_string_guess;
			CR_str prefix = known_string + unknown_str_new_block;
			
			for(char c = 0; c < 256; c++){
				known_string_guess = prefix + string(1, c); // add new guess character to end of string

				// encrypt our new guess
				CR_str encrypted_guess = blackbox(known_string_guess);

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
CR_str append_unknown_string_random_prefix_and_encrypt_ECB(CR_str message){
	// generate unknown key only once
	static CR_str random_key = generate_random_AES_key(AES::BLOCKSIZE);
	// create unknown string once
	static CR_str unknown_string = CR_str("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
												"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
												"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
												"YnkK", CR_str::BASE64_ENCODED);

	return ECB_AES_encrypt(message + unknown_string, random_key);
}

CR_str byte_at_a_time_ECB_decrypt_hard(){
	CR_str (*blackbox)(CR_str);
	blackbox = append_unknown_string_random_prefix_and_encrypt_ECB;

	/* First, find the block size of the cipher by feeding in successive test characters */
	CR_str known_string = CR_str("A");
	CR_str new_cipher = blackbox(known_string);
	int block_size = 0;
	int last_size = 0;
	CR_str unknown_str_new_block = CR_str();

	/* find unknown string size by feeding in empty string */
	int unknown_string_size = blackbox( CR_str() ).size();
	int unknown_string_blocks = unknown_string_size / AES::BLOCKSIZE;

	// find block size
	do{
		last_size = new_cipher.size();
		known_string += CR_str("A");
		new_cipher = blackbox(known_string);
		block_size++;
	}
	while(new_cipher.size() == last_size);

	/* Verify that the function is using ECB */
	if(CR_str::ECB_ENCRYPTION != detect_ECB_or_CBC_encryption(blackbox)){
		cout << "byte_at_a_time_ECB_decrypt_simple(): function is not using ECB encryption." << endl;

		return CR_str();
	}

	/* Solve each block consecutively, solving one byte at a time */
	CR_str previous_blocks = CR_str();
	for(int blk = 0; blk < unknown_string_blocks; blk++){
		unknown_str_new_block = CR_str();

		for(int byte = AES::BLOCKSIZE - 1; byte >= 0; byte--){
			// make partial string with dummy chars (A's)
			known_string = string(byte, 'A');

			// encrypt once using partial string
			CR_str encrypted_actual = blackbox(known_string);

			// add known bytes to end of test string - do this after we compute encrypted message we compare test cases to
			known_string += previous_blocks;

			// add different byte values to end of known_string, see if this matches known_string with no extra byte
			CR_str known_string_guess;
			CR_str prefix = known_string + unknown_str_new_block;

			//cout << unknown_str_new_block.as_base64() << " " << endl;

			for(char c = 0; c < 256; c++){
				known_string_guess = prefix + c; // add new guess character to end of string

				// encrypt our new guess
				CR_str encrypted_guess = blackbox(known_string_guess);

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


// this implementation accepts nonces up to 16 bytes. Nonces under 16 bytes are zero
// padded to 16 bytes. The nonce value is then incremented by 1 each round.
CR_str CTR_AES_encrypt(CR_str message, CR_str key, CR_str nonce){
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
		nonce = nonce.add_padding( CR_str::ZERO_PADDING, AES::CTR_COUNTER_SIZE );
	}

	// if message isn't completely divisible into 16 byte chunks,
	// last chunk is not padded since this is CTR mode
	// The last, uneven size chunk is merely XOR'd against the
	// corresponding subsection of the keystream
	int num_ciphers = ceil((float) message.size() / (float) AES::BLOCKSIZE);


	CR_str ciphertext = CR_str();
	CR_str cipher_input;
	CR_str counter;
	counter.fill(AES::CTR_COUNTER_SIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		CR_str plaintext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		cipher_input = nonce.little_endian() + counter.little_endian();
		CR_str encrypted_nonce = AES_cipher_encrypt(cipher_input, key);

		// TODO: IDEA: instead of copying blocks over, just use container as accumulator that gets XOR'd

		// add new ciphertext by XORing with encrypted nonce
		ciphertext += encrypted_nonce ^ plaintext;

		// add 1 to the integer represented by the string
		counter.increment();
	}

	return ciphertext;
}

CR_str CTR_AES_decrypt(CR_str message, CR_str key, CR_str nonce){
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
		nonce = nonce.add_padding( CR_str::ZERO_PADDING, AES::CTR_COUNTER_SIZE );
	}

	// if message isn't completely divisible into 16 byte chunks,
	// last chunk is not padded since this is CTR mode
	// The last, uneven size chunk is merely XOR'd against the
	// corresponding subsection of the keystream
	int num_ciphers = ceil((float) message.size() / (float) AES::BLOCKSIZE);

	CR_str plaintext = CR_str();

	CR_str cipher_input;
	CR_str counter;
	counter.fill(AES::CTR_COUNTER_SIZE, 0);

	for(int cipher = 0; cipher < num_ciphers; cipher++){
		CR_str ciphertext = message.substr(cipher * AES::BLOCKSIZE, AES::BLOCKSIZE);

		cipher_input = nonce.little_endian() + counter.little_endian();

		// TODO: IDEA: instead of copying blocks over, just use container as accumulator that gets XOR'd

		CR_str encrypted_nonce = AES_cipher_encrypt(cipher_input, key);

		// add new plaintext by XORing with encrypted nonce
		plaintext += encrypted_nonce ^ ciphertext;

		// add 1 to the integer represented by the string
		counter.increment();
	}

	return plaintext;
}


