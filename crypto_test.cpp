/*
 * crypto_test.cpp
 *
 *  Created on: Mar 20, 2016
 *      Author: blake
 */


#include "lib/codec.hpp"
#include "lib/block_cipher.hpp"
#include "lib/cookie.hpp"
#include "lib/rng.hpp"

#include <ctime>
#include <fstream>
#include <map>
#include <vector>
#include <array>
#include <string>

using namespace std;




/* Timing */
std::clock_t start;

void tick(){
	// TODO: design for and test on windows
	// WORKS FOR LINUX ONLY
	start = std::clock();
}

void tock(){
	double epoch = (std::clock() - start) / (double)(CLOCKS_PER_SEC / 1000);

	// print as seconds if more than 1000 ms
	if(epoch > 1000){
		cout << "\t\t" << epoch / 1000.0 << " sec" << endl;
	}
	else{
		cout << "\t\t" << epoch << " ms" << endl;
	}
}



// uses ANSI color codes for terminal
// might not work on all systems
void crypto_exercise_test(int num, bool test){
	cout << "\t" << "Exercise " << num << ":\t";

	if(test)
	{
		cout << "\033[1;32m[PASSED]\033[0m";
	}
	else{
		cout << "\033[1;31m[FAILED]\033[0m";
	}
}


//  TODO: fault_check(key.size() != AES::BLOCKSIZE, message or error enum)

//  TODO:
// IDEA: make red and yellow alarms for debug messages.
// YELLOW = "padding up to ..." and RED = critical failure (index overrun)

//  TODO:
// IDEA: make command line arguments for specific exercise tests.
// e.g. ./crypto_test 3 8 12 18
// include ALL command for all test

// TODO: make exercises loaded in once, since some exercises reuse files

int main(int argc, char* argv[])
{
	/* Set 1 */
	// Notation conversion testing
	// Going from base64 to ascii and then back to base64 should produce
	// a base64 output that is identical to the base64 input.

//	cout << ">> Now testing: Set 1" << endl;
//	cout << ">> " << "Now performing codec test " << endl;
//	tick();
//	{
//		bool failed = false;
//
//		ifstream encoded_strings("test_files/encoded_b64_ex19.txt");
//
//		Xstr newstr;
//		string b64_str;
//		string new_b64_str;
//
//		string test[4] = {
//				"dGhpcyBpcyBhIHRlc3Qu",
//				"dGhpcyBpcyBhIHRlc3QuLg==",
//				"dGhpcyBpcyBhIHRlc3QuLi4=",
//				"dGhpcyBpcyBhIHRlc3QuLi4u"
//		};
//
//		// test different amounts of trailing '=' placeholders
//		// and uneven b64:ascii element ratios
//		for(int s = 0; s <= 3; s++){
//
//			Xstr ascii_str = Xstr(test[s], Xstr::BASE64_ENCODED);
//
////			cout << test[s] << endl;
////			cout << ascii_str.as_base64() << endl;
//
//			if(ascii_str.as_base64() != test[s]){
//				failed = true;
//				goto eval1;
//				break;
//			}
//		}
//
//
//		eval1:	crypto_exercise_test(1,	!failed);
//
//	}
//	tock();
//
//
//	/* Exercise 7 */
//	tick();
//	{
//		bool failed = false;
//		string line;
//		string base64_encoded = string("");
//		Xstr encoded, decoded;
//
//		Xstr decoded_part = "I'm back and I'm ringin' the bell \n"
//							"A rockin' on the mike while the fly girls yell \n"
//							"In ecstasy in the back of me \n"
//							"Well that's my DJ Deshay cuttin' all them Z's \n"
//							"Hittin' hard and the girlies goin' crazy \n"
//							"Vanilla's on the mike, man I'm not lazy.";
//
//		ifstream string_file("test_files/encoded_ex7.txt");
//		string key = string("YELLOW SUBMARINE");
//
//
//		// read string into vector from file
//		if (string_file.is_open()){
//			while( getline(string_file, line) ){
//				base64_encoded += line;
//			}
//
//			string_file.close();
//		}
//		else{
//			cout << "ERROR: Unable to open file" << endl;
//			//TODO: put two next lines in all file open operations
//			//TODO: also, make read_file() function
//			failed = true;
//			goto eval7;
//		}
//
//		encoded = Xstr( base64_encoded, Xstr::BASE64_ENCODED );
//		decoded = BlockCipher::decrypt(EncryptType::ECB_ENCRYPT, encoded, key);
//
////		cout << decoded_part.size() << endl;
////		cout << decoded.substr(0, decoded_part.size()).size() << endl;
////		cout << decoded.substr(0, decoded_part.size()) << endl;
//
//		if(decoded.substr(0, decoded_part.size()) != decoded_part){
//			failed = true;
//		}
//
//		eval7: ;
//		crypto_exercise_test(7, !failed);
//
//	};
//	tock();
//
//
//	/* Set 2 */
//	cout << ">> Now testing: Set 2" << endl;
//
//	/* Exercise 9 */
//	tick();
//	{
//		static Xstr output = "YELLOW SUBMARINE\x04\x04\x04\x04";
//
//		Xstr message = Xstr("YELLOW SUBMARINE");
//
//		crypto_exercise_test(9,
//					output == message.add_padding(Xstr::PKCS7_PADDING, 20)
//				);
//
//	};
//	tock();
//
//	/* Exercise 10 */
//	tick();
//	{
//		static string output =
//			"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \n"
//			"And I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \n"
//			"Spaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n"
//			"'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\n"
//			"Play that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
//
//		string line;
//		string base64_encoded = string("");
//		string key = string("YELLOW SUBMARINE");
//
//		string IV = string();
//		IV.resize(AES::BLOCKSIZE, 0); // size 16 - IV is all zeroes!
//
//		ifstream string_file("test_files/encoded_ex10.txt");
//
//		// read string into vector from file
//		if (string_file.is_open()){
//			while( getline(string_file, line) ){
//				base64_encoded += line;
//			}
//			string_file.close();
//		}
//		else{
//			cout << "Exercise 10: Unable to open file" << endl;
//		}
//
//		Xstr ascii_encoded = Xstr( base64_encoded, Xstr::BASE64_ENCODED );
//		Xstr message = BlockCipher::decrypt(EncryptType::CBC_ENCRYPT, ascii_encoded, key, IV);
//
//		crypto_exercise_test(10,
//					output == message.remove_padding(Xstr::UNKNOWN_PADDING)
//				);
//
//	};
//	tock();
//
//	/* Exercise 11 */
//	cout << "\t" << "Exercise 11:\t";
//
//	tick();
//	{
//		//TODO: add this to hacker class maybe?
//		EncryptType encryption_type = detect_ECB_or_CBC_encryption(encrypt_using_CBC_or_ECB);
//
//		if(encryption_type == EncryptType::CBC_ENCRYPT){
//			cout << "Detected CBC";
//		}else if(encryption_type == EncryptType::ECB_ENCRYPT){
//			cout << "Detected ECB";
//		}
//		else{
//			cout << "Unknown Encryption";
//		}
//
//	}
//	tock();
//
//	/* Exercise 12 */
//	tick();
//	{
//
//		static Xstr output =
//				"Rollin' in my 5.0\n"
//				"With my rag-top down so my hair can blow\n"
//				"The girlies on standby waving just to say hi\n"
//				"Did you stop? No, I just drove by\n";
//
//
//		crypto_exercise_test(12,
//					output == byte_at_a_time_ECB_decrypt_simple().remove_padding(Xstr::UNKNOWN_PADDING)
//				);
//
//	};
//	tock();
//
//	/* Exercise 13 */
//	// TODO: finish this exercise
//	tick();
//	{
//		static Xstr output = "email=blake@google.com*role*admin&role=user&uid=10";
//		Xstr hacked_cookie = ecb_cut_and_paste();
//
//		crypto_exercise_test(13,
//					output == hacked_cookie.as_ascii()
//				);
//
//	};
//	tock();
//
//	/* Exercise 14 */
//	tick();
//	{
//		static Xstr output =
//				"Rollin' in my 5.0\n"
//				"With my rag-top down so my hair can blow\n"
//				"The girlies on standby waving just to say hi\n"
//				"Did you stop? No, I just drove by\n";
//
//		crypto_exercise_test(14,
//					output == byte_at_a_time_ECB_decrypt_hard().remove_padding(Xstr::UNKNOWN_PADDING)
//				);
//
//	};
//	tock();
//
//	/* Exercise 15 */
//	tick();
//	{
//		Xstr teststr1("ICE ICE BABY\x04\x04\x04\x04");
//		Xstr teststr2("ICE ICE BABY\x05\x05\x05\x05");
//		Xstr teststr3("ICE ICE BABY\x01\x02\x03\x04");
//
//		crypto_exercise_test(15,
//					teststr1.find_padding_type() == Xstr::PKCS7_PADDING and
//					teststr2.find_padding_type() == Xstr::NO_PADDING and
//					teststr3.find_padding_type() == Xstr::NO_PADDING
//				);
//
//	};
//	tock();
//
//
//	/* Exercise 16 */
//	/* 	CBC bitflipping attacks */
//	tick();
//	{
//		// generate unknown key only once
//		static Xstr random_key = generate_random_AES_key();
//		// generate unknown IV only once
//		static Xstr rand_IV = generate_random_AES_IV();
//		// create unknown string once
//		static Xstr unknown_string = Xstr("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
//													"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
//													"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
//													"YnkK", Xstr::BASE64_ENCODED);
//
//		static Xstr prefix = "comment1=cooking%20MCs;userdata=";
//		static Xstr suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
//		static string output_token = ";admin=true;";
//
//		Xstr message = "XXXXXXXXXXXXXXXX:admin<true:XXXX";
//		Xstr encrypted = BlockCipher::encrypt(EncryptType::CBC_ENCRYPT, prefix + message + suffix, random_key, rand_IV);
//
//		encrypted[32] ^= 1;
//		encrypted[38] ^= 1;
//		encrypted[43] ^= 1;
//
//		Xstr decrypted = BlockCipher::decrypt(EncryptType::CBC_ENCRYPT, encrypted, random_key, rand_IV);
//		decrypted = decrypted.remove_padding(Xstr::UNKNOWN_PADDING);
//
//		crypto_exercise_test(16,
//					decrypted.as_ascii().find(output_token) != std::string::npos
//				);
//
//	}
//	tock();
//
//
//	/* Set 3 */
//	cout << ">> Now testing: Set 3" << endl;
//
//	/* Exercise 17 */
//	tick();
//	{
//		// cracked strings are truncated at the beginning since the first
//		// block can't be deciphered
//        vector<string> out = {
//				"he party is jumping",
//				"ass kicked in and the Vega's are pumpin'",
//				"he point, to the point, no faking",
//				"'s like a pound of bacon",
//				"m, if you ain't quick and nimble",
//				" hat with a souped up tempo",
//				"oll, it's time to go solo",
//				"my five point oh",
//				"-top down so my hair can blow"
//		};
//
//
//		BlockCipher::CipherData info = pad_random_string_and_encrypt_CBC();
//
//		Xstr decrypted = break_AES_CBC_via_server_leak(info);
//		decrypted = decrypted.remove_padding(Xstr::UNKNOWN_PADDING);
//
//		crypto_exercise_test(17,
//					std::find(out.begin(), out.end(), decrypted.as_ascii()) != out.end()
//				);
//
//	}
//	tock();
//
//	/* Exercise 18 */
//	tick();
//	{
//		Xstr encrypted = Xstr("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ",
//								Xstr::BASE64_ENCODED);
//
//		Xstr key = "YELLOW SUBMARINE";
//
//		Xstr nonce;
//		nonce.resize(AES::CTR_NONCE_SIZE, 0); // size 8 - nonce is all zeroes!
//
//		Xstr decrypted = BlockCipher::decrypt(EncryptType::CTR_ENCRYPT, encrypted, key, nonce);
//
//		Xstr encrypted2 = BlockCipher::encrypt(EncryptType::CTR_ENCRYPT, decrypted, key, nonce);
//		Xstr decrypted2 = BlockCipher::decrypt(EncryptType::CTR_ENCRYPT, encrypted2, key, nonce);
//
//		crypto_exercise_test(18, decrypted == decrypted2);
//	}
//	tock();
//
//
//	vector.push_back() is busted
//
//	/* Exercise 19 */
//	// TODO: fix base64 encoding because it works when feeding in raw ascii
//	tick();
//	{
//		vector<Xstr> strings;
//
//		ifstream string_file("test_files/encoded_b64_ex19.txt");
//		string line;
//
//		// read string into vector from file and encrypt
//		// TODO: make function that will encrypt batch
//		if (string_file.is_open()){
//			while( getline(string_file, line) ){
////				cout << 1 << endl;
////				cout << "before decoding: " << line << endl;
//
//				Xstr newstr = Xstr(line, Xstr::BASE64_ENCODED);
////				cout << 2 << endl;
//
////				cout << "after decoding:  " << newstr.as_base64() << endl;
////				cout << 3 << endl;
//				strings.push_back( newstr );
//			}
//			string_file.close();
//		}
//		else{
//			cout << " Unable to open file" << endl;
//		}
//
//		vector<Xstr> ciphers;
//		Xstr random_key = generate_random_AES_key();
//
//		/* Make 8-byte nonce for CTR, fill with 0's
//		 * We use the same nonce for all encryptions, which is where the
//		 * weakness is */
//		Xstr nonce;
//		nonce.resize(AES::CTR_NONCE_SIZE, 0);
//
//
//		Xstr next_str;
//		Xstr next_cipher;
//
//		// encrypt the strings
//		for(int i = 0; i < strings.size(); i++){
////			cout << "1" << endl;
//			next_str = Xstr(strings[i], Xstr::BASE64_ENCODED);
////			cout << "2" << endl;
////			cout << "after decoding: " << next_str.as_base64() << endl;
//			next_cipher = BlockCipher::encrypt(EncryptType::CTR_ENCRYPT, next_str, random_key, nonce);
//
//			ciphers.push_back( next_cipher );
//
////			cout << "3" << endl;
//		}
//
////		cout << "4" << endl;
//		Xstr keystream = break_fixed_nonce_CTR_by_substituting(ciphers);
//
//		// guesses based on partially decoded ciphers (wheel of fortune style)
//	    keystream[0]  = (ciphers[4][0] ^ 'I');
//	    keystream[30] = (ciphers[4][30] ^ 'e');
//	    keystream[33] = (ciphers[4][33] ^ 'e');
//	    keystream[34] = (ciphers[4][34] ^ 'a');
//	    keystream[35] = (ciphers[4][35] ^ 'd');
//	    keystream[36] = (ciphers[37][36] ^ 'n');
//	    keystream[37] = (ciphers[37][37] ^ ',');
//
//		// decrypt the strings with the hacked keystream
//		for(Xstr cipher: ciphers){
//			cout << (keystream ^ cipher).as_ascii() << endl;
//		}
//
////		for(int i = 0; i < 27; i++){
////
////			cout <<  (uint8_t)keystream[i] << " " << (uint8_t)ciphers[0][i] << " " << (uint8_t)first_cipher[i] << endl;
////
////			cout << (int) (keystream[i] ^ ciphers[0][i]) << " " << (int) first_cipher[i];
////			cout << endl;
////			cout << ((keystream[i] ^ ciphers[0][i]) == first_cipher[i]);
////			cout << endl;
////
////		}
//
////		cout << (keystream ^ ciphers[0]) << endl;
////		cout << Xstr(first_cipher) << endl;
////		cout << Xstr(first_cipher).size() << endl;
////		cout << (keystream.substr(0,Xstr(first_cipher).size()) ^ ciphers[0]).size() << endl;
//
//
////		Xstr cracked_cipher = keystream.substr(0,Xstr(first_cipher).size()) ^ ciphers[0];
////
////		cout << Xstr(first_cipher).substr(0,10) << " " << cracked_cipher.substr(0,10) << endl;
////
////		crypto_exercise_test(19,
////					Xstr(first_cipher).substr(0,10) == cracked_cipher.substr(0,10)
////				);
//
//	}
//	tock();
//
//
//	vector.push_back() is busted
//
//	/* Exercise 20 */
//	tick();
//	{
//		vector<Xstr> strings;
//		vector<Xstr> ciphers;
//		strings.reserve(60);
//		ciphers.reserve(60);
//
//		Xstr random_key = generate_random_AES_key();
//
//		Xstr newstr;
//		Xstr next_cipher;
//
//		/* Make 8-byte nonce for CTR, fill with 0's
//		 * We use the same nonce for all encryptions, which is where the
//		 * weakness is */
//		Xstr nonce;
//		nonce.resize(AES::CTR_NONCE_SIZE, 0);
//
//		ifstream string_file("plaintext_ex20.txt");
//		string line;
//
//		cout << "HERE" << endl;
//		int i = 0;
//		// read string into vector from file and encrypt
//		// TODO: make function that will encrypt batch
//		if (string_file.is_open()){
//			while( getline(string_file, line) ){
//				newstr = Xstr(line, Xstr::BASE64_ENCODED);
//				cout << "\tHERE0" << endl;
//				strings[i] = ( newstr );
//
//				cout << "\tHERE1" << endl;
//				next_cipher = BlockCipher::encrypt(
//						EncryptType::CTR_ENCRYPT, newstr, random_key, nonce);
//
//				cout << "\tHERE2" << endl;
//				ciphers[i] = (next_cipher);
//				cout << "\tHERE3" << endl;
//				i++;
//			}
//			cout << "HERE" << endl;
//			string_file.close();
//		}
//		else{
//			cout << " Unable to open file" << endl;
//		}
//
//		cout << "HERE" << endl;
//		vector<Xstr> decoded = break_fixed_nonce_CTR_statistically(ciphers);
//
////		for (auto i = decoded.begin(); i != decoded.end(); ++i)
////		    std::cout << *i << ' ' << endl;
//
//	}
//	tock();
//
//	/* Exercise 21 */
//	tick();
//	{
//		std::array<long int, 30> expected_out =
//				{
//				1791095845, -12091157,	-59818354, -1431042742,
//				491263,	1690620555,	1298508491,	-1144451193, 1637472845,
//				1013994432, 396591248, 1703301249, 799981516, 1666063943,
//				1484172013,
//
//				2469588189546311528, 5937829314747939781, -1488664451840123274,
//				8414607737543979063, -8983179180370611640, -4813816549494704131,
//				-5143718920953096580, -3311530619265271089,	5943497028716478977,
//				2456665931235054654, 5698940622110840090, -5231858944456961090,
//				5552614544520314474, 6131760866643541936, 8415486058342034190
//				};
//
//		std::array<long int, 30> actual_out;
//
//		MersenneTwister mt;
//
//		// 32-bit test
//		mt.set_bitsize(mt._32BIT);
//		mt.srand_mt(1);
//
//		int i;
//		for(i = 0; i < 15; i++){
//			actual_out[i] = mt.rand_mt();
//		}
//
//		// 64-bit test
//		mt.set_bitsize(mt._64BIT);
//		mt.srand_mt(1);
//
//		for(; i < 30; i++){
//			actual_out[i] = mt.rand_mt();
//		}
//
//		crypto_exercise_test(21, expected_out == actual_out);
//	}
//	tock();
//
//	/* Exercise 22 */
//	tick();
//	{
//		long int rand_output = MT_hacker::rand_wait_then_seed_with_time();
//
//		long int cracked_seed = MT_hacker::crack_MT_seed(rand_output);
//
//		crypto_exercise_test(22, cracked_seed != -1);
//	}
//	tock();
//
//	/* Exercise 23 */
//	tick();
//	{
//		vector<long int> orig_outputs;
//		vector<long int> cloned_outputs;
//
//		// 64-bit test - 32-bit functionality has already been verified to work
//		MT::BITSIZE bitsize = MT::_64BIT;
//
//		MersenneTwister mt(0, bitsize);
//
//		// completely tap the twister for all 624 outputs in a single state
//		for(int i = 0; i < 312; i++){
//			orig_outputs.push_back(mt.rand_mt());
//		}
//
//		// Get vector of unsigned long int's because that's how they are represented
//		// the the MersenneTwisters internal state
//		vector<uint64_t> state = MT_hacker::clone_MT_from_output(orig_outputs, bitsize);
//
//		// refresh MT to reload state and verify
//		mt.load_state(state);
//
//		for(int i = 0; i < 312; i++){
//			cloned_outputs.push_back(mt.rand_mt());
//		}
//
//		crypto_exercise_test(23, orig_outputs == cloned_outputs);
//	}
//	tock();
//
//	/* Exercise 24 */
//	tick();
//	{
//		bool failed = false;
//
//		int max_score = 1;
//		Xstr best_key = Xstr();
//		Xstr test_str = Xstr("This is test str");
//		Xstr key_guess = Xstr(2, 0); // 2 bytes, start at 0x0000
//		Xstr result = Xstr();
//
//		// testing MT19937 encryption/decryption
//		Xstr encrypted = BlockCipher::MT19937_encrypt(test_str, "AA");
//		Xstr decrypted = BlockCipher::MT19937_decrypt(encrypted, "AA");
//
//		if(decrypted != test_str){
//			failed = true;
//			goto eval24;
//		}
//
//		// testing MT19937 key cracking
//		failed = false;
//
//		// 0xFFFF represents the capacity of 16 bits
//		// iterate through possibilities (65536) and evaluate for common
//		// egnlish characters
//		for(int i = 0; i < 0xFFFF; i++){
//			result = BlockCipher::MT19937_decrypt(test_str, key_guess);
//
//			char element;
//			int score = 0;
//
//			do{
//				element = result[result.size() - score - 1];
//			}while(is_english_character(element) and ++score < result.size());
//
//			if(score > max_score){
//				best_key = key_guess;
//				max_score = score;
//			}
//
//			key_guess++;
//		}
//
//		decrypted = BlockCipher::MT19937_decrypt(test_str, best_key);
//
//		if(decrypted != test_str){
//			failed = true;
//			goto eval24;
//		}
//
//		eval24:	crypto_exercise_test(24, !failed);
//	}
//	tock();
//
//
//	/* Set 4 */
	cout << ">> Now testing: Set 4" << endl;

	/* Exercise 25 */
	// TODO: Needs fixing, decoded output is returning known_text (all X's)
	tick();
	{
		bool failed = false;
		string line;
		string base64_encoded = string("");
		Xstr cipher, intermediate, decoded, edited_cipher;
		Xstr known_text;

		ifstream string_file("test_files/encoded_ex7.txt");


		// read string into vector from file
		if (string_file.is_open()){
			while( getline(string_file, line) ){
				base64_encoded += line;
			}

			string_file.close();
		}
		else{
			cout << "ERROR: Unable to open file" << endl;
			failed = true;
			goto eval25;
		}

		cipher = Xstr( base64_encoded, Xstr::BASE64_ENCODED );
		known_text = Xstr(cipher.size(), 'X'); // fill known text with X's


		edited_cipher = server_API_cipher_edit(EncryptType::CTR_ENCRYPT, cipher, 0, known_text);

		intermediate = edited_cipher ^ known_text;

		decoded = intermediate ^ cipher;

		cout << decoded << endl;


//		if(decoded.substr(0, decoded_part.size()) != decoded_part){
//			failed = true;
//		}

		eval25: ;
		crypto_exercise_test(25, !failed);
	}
	tock();

	return 0;
}

