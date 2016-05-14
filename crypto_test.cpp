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

int main(int argc, char* argv[])
{
	/* Set 1 */
	// notation conversion testing
//	cout << ">> " << "Now performing codec test " << endl;
//	tick();
//	{
//		string test = string("AdGhpcyBpcyBhIHRlc3Qh");
//
//		Xstr ascii = Xstr(test, Xstr::BASE64_ENCODED);
//
//		Xstr tests = Xstr("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove ", Xstr::ASCII_ENCODED);
//
//		cout << test << endl;
//		cout << ascii.as_base64() << endl;
//		cout << ascii.as_base64() << endl;
//		cout << ascii.as_ascii() << endl;
//		cout << test << endl;
//		cout << tests.as_base64() << endl;

//		cout << (tests.as_base64() == ascii.as_base64()) << endl;

//		bool failed = false;
//
//		for(int s = 0; s < 4; s++){
//			orig_test += (char) generate_rand_num_between(65, 90);
//			test = orig_test;
//
//			// fiddle with last 3 characters to test the uneven symbol size
//			for(int i = 0; i < 3; i++){
//				ascii = Xstr(test, Xstr::BASE64_ENCODED);
//
////				cout << ascii.as_base64() << endl;
//				if(orig_test != ascii.as_base64()){
//					failed = true;
//				}
//
//				test += "=";
//			}
//		}
//
//		//		cout << unknown_string.pretty(CR_str::ASCII_ENCODED) << endl;
//
//		crypto_exercise_test(1,
//					!failed
//				);
//	}
//	tock();
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
//		static Xstr output =
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
//		ifstream string_file("encoded_ex10.txt");
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
//        vector<string> out = {
//				"he party is jumpi",
//				"ass kicked in and the Vega's are pumpi",
//				"he point, to the point, no fakin",
//				"'s like a pound of baco",
//				"m, if you ain't quick and nimble",
//				" when I hear a cymba",
//				" hat with a souped up temp",
//				"oll, it's time to go so",
//				"my five point ",
//				"-top down so my hair can blow"
//		};
//
//		BlockCipher::CipherData info = pad_random_string_and_encrypt_CBC();
//
//		Xstr decrypted = break_AES_CBC_via_server_leak(info);
//		decrypted = decrypted.remove_padding(Xstr::UNKNOWN_PADDING);
//
//		crypto_exercise_test(17,
//					find(out.begin(), out.end(), decrypted.as_ascii()) != out.end()
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
//	/* Exercise 19 */
//	// TODO: fix base64 encoding because it works when feeding in raw ascii
//	tick();
//	{
//		Xstr first_cipher = Xstr(
//				"I have met them atCloseOfda",
//				Xstr::ASCII_ENCODED);
//
//		const string strings[40] = {
//				"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
//				"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
//				"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
//				"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
//				"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
//				"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
//				"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
//				"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
//				"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
//				"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
//				"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
//				"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
//				"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
//				"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
//				"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
//				"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
//				"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
//				"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
//				"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
//				"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
//				"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
//				"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
//				"U2hlIHJvZGUgdG8gaGFycmllcnM/",
//				"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
//				"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
//				"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
//				"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
//				"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
//				"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
//				"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
//				"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
//				"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
//				"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
//				"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
//				"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
//				"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
//				"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
//				"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
//				"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
//				"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
//		};
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
//		// encrypt the strings
//		for(int in = 0; in < 40; in++){
////			cout << Xstr(strings[in], Xstr::BASE64_ENCODED).as_ascii() << endl;
//			Xstr next_str = Xstr(strings[in], Xstr::BASE64_ENCODED);
//			Xstr next_cipher = BlockCipher::encrypt(EncryptType::CTR_ENCRYPT, next_str, random_key, nonce);
//
//			ciphers.push_back( next_cipher );
//		}
//
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
////			cout << (keystream ^ cipher).as_ascii() << endl;
//		}
//
//		for(int i = 0; i < 27; i++){
//
////			cout <<  (uint8_t)keystream[i] << " " << (uint8_t)ciphers[0][i] << " " << (uint8_t)first_cipher[i] << endl;
//
////			cout << (int) (keystream[i] ^ ciphers[0][i]) << " " << (int) first_cipher[i];
////			cout << endl;
////			cout << ((keystream[i] ^ ciphers[0][i]) == first_cipher[i]);
////			cout << endl;
//
//		}
//
////		cout << (keystream ^ ciphers[0]) << endl;
////		cout << Xstr(first_cipher) << endl;
////		cout << Xstr(first_cipher).size() << endl;
////		cout << (keystream.substr(0,Xstr(first_cipher).size()) ^ ciphers[0]).size() << endl;
//
//		crypto_exercise_test(19,
//					Xstr(first_cipher).substr(0,10) == Xstr((keystream.substr(0,Xstr(first_cipher).size()) ^ ciphers[0])).substr(0,10)
//				);
//
//	}
//	tock();
//
//	/* Exercise 20 */
//	tick();
//	{
//		vector<Xstr> strings;
//		vector<Xstr> ciphers;
//		Xstr random_key = generate_random_AES_key();
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
//		// read string into vector from file and encrypt
//		// TODO: make function that will encrypt batch
//		if (string_file.is_open()){
//			while( getline(string_file, line) ){
//				Xstr newstr = Xstr(line, Xstr::BASE64_ENCODED);
//				strings.push_back( newstr );
//
//				Xstr next_cipher = BlockCipher::encrypt(
//						EncryptType::CTR_ENCRYPT, newstr, random_key, nonce);
//
//				ciphers.push_back(next_cipher);
//			}
//			string_file.close();
//		}
//		else{
//			cout << " Unable to open file" << endl;
//		}
//
//		vector<Xstr> decoded = break_fixed_nonce_CTR_statistically(ciphers);
//
////		for (auto i = decoded.begin(); i != decoded.end(); ++i)
////		    std::cout << *i << ' ' << endl;
//
//	}
//	tock();

	/* Exercise 21 */
	tick();
	{
		std::array<long int, 30> expected_out =
				{
				1791095845, -12091157,	-59818354, -1431042742,
				491263,	1690620555,	1298508491,	-1144451193, 1637472845,
				1013994432, 396591248, 1703301249, 799981516, 1666063943,
				1484172013,

				2469588189546311528, 5937829314747939781, -1488664451840123274,
				8414607737543979063, -8983179180370611640, -4813816549494704131,
				-5143718920953096580, -3311530619265271089,	5943497028716478977,
				2456665931235054654, 5698940622110840090, -5231858944456961090,
				5552614544520314474, 6131760866643541936, 8415486058342034190
				};

		std::array<long int, 30> actual_out;

		// 32-bit test
		MersenneTwister::set_bitsize(MersenneTwister::_32BIT);
		MersenneTwister::srand_mt(1);

		int i;
		for(i = 0; i < 15; i++){
			actual_out[i] = MersenneTwister::rand_mt();
		}

		// 64-bit test
		MersenneTwister::set_bitsize(MersenneTwister::_64BIT);
		MersenneTwister::srand_mt(1);

		for(; i < 30; i++){
			actual_out[i] = MersenneTwister::rand_mt();
		}

		crypto_exercise_test(21, expected_out == actual_out);
	}
	tock();


	return 0;
}

