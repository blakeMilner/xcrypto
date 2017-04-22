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

// TODO: make files loaded in once, since some exercises reuse files

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
//			cout << test[s] << endl;
//			cout << ascii_str.as_base64() << endl << endl;
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
//	tick();
//	{
//		bool failed = false;
//
//		Xstr str1("1c0111001f010100061a024b53535009181c", Xstr::HEX_ENCODED);
//		Xstr str2("686974207468652062756c6c277320657965", Xstr::HEX_ENCODED);
//		Xstr str3("746865206b696420646f6e277420706c6179", Xstr::HEX_ENCODED);
//
//		if((str1 ^ str2) != str3)
//			failed = true;
//
//		eval2:	crypto_exercise_test(2,	!failed);
//
//	}
//	tock();
//
//
//
//	/* Exercise 3 */
//	// Single-byte XOR cipher
//	tick();
//	{
//		bool failed = false;
//
//		Xstr test_string("1b37373331363f78151b7f2b783431333"
//						"d78397828372d363c78373e783a393b3736", Xstr::HEX_ENCODED);
//
//		Xstr output("Cooking MC's like a pound of bacon");
//
//		decoded_message message = solve_single_byte_xor( test_string );
//
//		if(message.key_found){
//			if(message.decoded != output)
//				failed = true;
//		}
//
//		crypto_exercise_test(3, !failed);
//
//	};
//	tock();
//
//	/* Exercise 4 */
//	// Detect single-character XOR
//	tick();
//	{
//		bool failed = false;
//
//		vector<Xstr> possible_strings;
//		string line;
//		ifstream string_file("test_files/encoded_ex4.txt");
//		Xstr output("Now that the party is jumping\n");
//
//		int max_idx = -1;
//		bool max_found = false;
//
//		decoded_message max_message;
//		max_message.score = 0;
//		max_message.decoded = Xstr();
//
//		// read string into vector from file
//		if (string_file.is_open()){
//			while( getline(string_file, line) ){
//				Xstr ascii_string(line, Xstr::HEX_ENCODED );
//				possible_strings.push_back( ascii_string );
//			}
//
//			string_file.close();
//		}
//		else{
//			cout << "Unable to open file" << endl;
//			failed = true;
//			goto eval4;
//		}
//
//		// iterate through potential strings and find the best solution for each.
//		// Regard string with highest score as encoded string
//		for(Xstr next_str: possible_strings){
//			decoded_message message = solve_single_byte_xor( next_str );
//
//			if(message.score > max_message.score){
//				max_found = true;
//				max_message.score = message.score;
//				max_message.decoded = message.decoded;
//			}
//		}
//
//		if(max_message.decoded != output)
//			failed = true;
//
//		eval4:
//			crypto_exercise_test(4, !failed);
//
//	};
//	tock();
//
//	/* Exercise 5 */
//	// Implement repeating-key XOR
//	tick();
//	{
//		bool failed = false;
//
//		Xstr expected = Xstr(
//				"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2"
//				"a26226324272765272a282b2f20430a652e2c652a3124333a653e2b20"
//				"27630c692b20283165286326302e27282f", Xstr::HEX_ENCODED);
//
//		Xstr message = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
//		Xstr key = "ICE";
//
//		Xstr encoded = message.XOR_wraparound(key);
//
//		if(encoded == expected)
//			failed = false;
//
//		crypto_exercise_test(5, !failed);
//
//	};
//	tock();
//
//	/* Exercise 6 */
//	// Break repeating-key XOR
//	tick();
//	{
//		bool failed = false;
//
//		Xstr decoded_part = "I'm back and I'm ringin' the bell \n"
//							"A rockin' on the mike while the fly girls yell \n"
//							"In ecstasy in the back of me \n"
//							"Well that's my DJ Deshay cuttin' all them Z's \n"
//							"Hittin' hard and the girlies goin' crazy \n"
//							"Vanilla's on the mike, man I'm not lazy.";
//
//		string line;
//		string base64_encoded = string("");
//		ifstream string_file("test_files/encoded_ex6.txt");
//
//		Xstr ascii_encoded;
//		decoded_message message;
//		Xstr decoded;
//
//		// testing hamming distance - should be 37
//		int hamming_dist = Xstr("this is a test").hamming_distance("wokka wokka!!!");
//
//		if(hamming_dist != 37){
//			failed = true;
//			goto eval6;
//		}
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
//			failed = true;
//			goto eval6;
//		}
//
//		ascii_encoded = Xstr(base64_encoded, Xstr::BASE64_ENCODED );
//		message = solve_repeating_key_xor( ascii_encoded );
//
//		decoded = ascii_encoded.XOR_wraparound(message.key);
//
//		if(decoded.substr(0, decoded_part.size()) != decoded_part)
//			failed = true;
//
//		eval6: ;
//		crypto_exercise_test(6, !failed);
//
//	};
//	tock();
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
//		// read string in from file
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
//	/* Exercise 8 */
//	tick();
//	{
//		bool failed = false;
//
//		Xstr expected_ECB_cipher = Xstr(
//				"D880619740A8A19B7840A8A31C810A3D08649AF70DC06F4FD5D2D69C744C"
//				"D283E2DD052F6B641DBF9D11B0348542BB5708649AF70DC06F4FD5D2D69C"
//				"744CD2839475C9DFDBC1D46597949D9C7E82BF5A08649AF70DC06F4FD5D2"
//				"D69C744CD28397A93EAB8D6AECD566489154789A6B0308649AF70DC06F4F"
//				"D5D2D69C744CD283D403180C98C8F6DB1F2A3F9C4040DEB0AB51B29933F2"
//				"C123C58386B06FBA186A", Xstr::HEX_ENCODED);
//
//		ifstream string_file("test_files/encoded_ex8.txt");
//
//		vector<Xstr> possible_ciphers;
//		string line;
//		Xstr ECB_found;
//
//
//		// read string into vector from file
//		if (string_file.is_open()){
//			while( getline(string_file, line) ){
//				Xstr ascii_string = Xstr( line, Xstr::HEX_ENCODED );
//				possible_ciphers.push_back( ascii_string );
//			}
//
//			string_file.close();
//		}
//		else{
//			failed = true;
//			goto eval8;
//			cout << "ERROR: Unable to open file" << endl;;
//		}
//
//		// iterate through ciphers and see if they are ECB encoded
//		for(Xstr cipher: possible_ciphers){
//			if( detect_ECB_AES_encryption( cipher ) ){
//				ECB_found = cipher;
//				break;
//			}
//		}
//
//		if(expected_ECB_cipher != ECB_found)
//			failed = true;
//
//		eval8: ;
//		crypto_exercise_test(8, !failed);
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
//		// read string in from file
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
//		static Xstr unknown_string = Xstr(
//				"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
//				"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
//				"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
//				"YnkK", Xstr::BASE64_ENCODED);
//
//		static Xstr prefix = "comment1=cooking%20MCs;userdata=";
//		static Xstr suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
//		static string admin_token = ";admin=true;";
//
//		Xstr message = "XXXXXXXXXXXXXXXX:admin<true:XXXX";
//		Xstr encrypted = BlockCipher::encrypt(EncryptType::CBC_ENCRYPT, prefix + message + suffix, random_key, rand_IV);
//
//		// in the attack message we chose values for the tokens of interest
//		// such that we can just XOR them with 0b01 to obtain the desired tokens
//		encrypted[32] ^= 1;
//		encrypted[38] ^= 1;
//		encrypted[43] ^= 1;
//
//		Xstr decrypted = BlockCipher::decrypt(EncryptType::CBC_ENCRYPT, encrypted, random_key, rand_IV);
//		decrypted = decrypted.remove_padding(Xstr::UNKNOWN_PADDING);
//
//		crypto_exercise_test(16,
//					// find doesn't reach end of string
//					decrypted.as_ascii().find(admin_token) != std::string::npos
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
	/* Exercise 19 */
	// TODO: fix base64 encoding because it works when feeding in raw ascii
	tick();
	{
		Xstr keystream("Z/kf0FmwkR2EwZr1qdZfgqaoWbSlLy/QGY/VRRhA9LAAA===", Xstr::BASE64_ENCODED);

		string strings[38] = {
				"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
				"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
				"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
				"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
				"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
				"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
				"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
				"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
				"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
				"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
				"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
				"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
				"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
				"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
				"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
				"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
				"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
				"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
				"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
				"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
				"U2hlIHJvZGUgdG8gaGFycmllcnM/",
				"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
				"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
				"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
				"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
				"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
				"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
				"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
				"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
				"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
				"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
				"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
				"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
				"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
				"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
				"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
				"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		};

		vector<Xstr> ciphers;
		Xstr random_key("Rfh9orvO75Iba9PsvseQPg==",  Xstr::BASE64_ENCODED);


		/* Make 8-byte nonce for CTR, fill with 0's
		 * We use the same nonce for all encryptions, which is where the
		 * weakness is */
		Xstr nonce;
		nonce.resize(AES::CTR_NONCE_SIZE, 0);


		Xstr next_str;
		Xstr next_cipher;
		Xstr newstr;
		string s;

		// encrypt the strings
		for(int i = 0; i < 37; i++){
			newstr = Xstr(strings[i], Xstr::BASE64_ENCODED);

			next_cipher = BlockCipher::encrypt(EncryptType::CTR_ENCRYPT, newstr, random_key, nonce);

			ciphers.push_back( next_cipher );
		}

		// get keystream with partially solved characters
		Xstr cracked_keystream = break_fixed_nonce_CTR_by_substituting(ciphers);

		// I could waste my time guessing and complete the keystream, but I
		// have better things to do :)

		crypto_exercise_test(19,
					keystream == cracked_keystream
				);

	}
	tock();
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
//	cout << ">> Now testing: Set 4" << endl;
//
//	/* Exercise 25 */
//	// TODO: Needs fixing, decoded output is returning known_text (all X's)
//	tick();
//	{
//		bool failed = false;
//		string line;
//		string base64_encoded = string("");
//		Xstr cipher, intermediate, decoded, edited_cipher;
//		Xstr known_text;
//
//		ifstream string_file("test_files/encoded_ex7.txt");
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
//			failed = true;
//			goto eval25;
//		}
//
//		cipher = Xstr( base64_encoded, Xstr::BASE64_ENCODED );
//		known_text = Xstr(cipher.size(), 'X'); // fill known text with X's
//
//
//		edited_cipher = server_API_cipher_edit(EncryptType::CTR_ENCRYPT, cipher, 0, known_text);
//
//		intermediate = edited_cipher ^ known_text;
//
//		decoded = intermediate ^ cipher;
//
//		cout << decoded << endl;
//
//
////		if(decoded.substr(0, decoded_part.size()) != decoded_part){
////			failed = true;
////		}
//
//		eval25: ;
//		crypto_exercise_test(25, !failed);
//	}
//	tock();
//
//	// TODO: Exercise 26 done but it seems too easy... must take another look later."
//	/* Exercise 26 */
//	// CTR bit flipping attacks
//	tick();
//	{
//		// generate unknown key only once
//		static Xstr random_key = generate_random_AES_key();
//		// generate unknown nonce only once
//		static Xstr rand_nonce = generate_random_nonce(AES::CTR_NONCE_SIZE);
//		// create unknown string once
//		static Xstr unknown_string = Xstr(
//				"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
//				"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
//				"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
//				"YnkK", Xstr::BASE64_ENCODED);
//
//		static Xstr prefix = "comment1=cooking%20MCs;userdata=";
//		static Xstr suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
//		static string admin_token = ";admin=true;";
//
//		Xstr message = "XXXXXXXXXXXXXXXX:admin<true:XXXX";
//		Xstr encrypted = BlockCipher::encrypt(EncryptType::CTR_ENCRYPT, prefix + message + suffix, random_key, rand_nonce);
//
//		// in the attack message we chose values for the tokens of interest
//		// such that we can just XOR them with 0b01 to obtain the desired tokens
//		//
//		// NOTE: the indices are the only thing different between this and Ex. 16
//		// 		Not sure why the indices should be different though... explanation needed
//		encrypted[48] ^= 1;
//		encrypted[54] ^= 1;
//		encrypted[59] ^= 1;
//
//		Xstr decrypted = BlockCipher::decrypt(EncryptType::CTR_ENCRYPT, encrypted, random_key, rand_nonce);
//		decrypted = decrypted.remove_padding(Xstr::UNKNOWN_PADDING);
//
//		crypto_exercise_test(26,
//					// find doesn't reach end of string
//					decrypted.as_ascii().find(admin_token) != std::string::npos
//				);
//	};
//	tock();

	return 0;
}

