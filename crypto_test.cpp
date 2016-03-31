/*
 * crypto_test.cpp
 *
 *  Created on: Mar 20, 2016
 *      Author: blake
 */


#include "lib/codec.hpp"
#include "lib/block_cipher.hpp"
#include "lib/cookie.hpp"

#include <ctime>
#include <fstream>
#include <map>
#include <vector>

using namespace std;




/* Timing */
std::clock_t start;

void tick(){
	// WORKS FOR LINUX ONLY
	start = std::clock();
}

void tock(){
	cout << "\t\t" << (std::clock() - start) / (double)(CLOCKS_PER_SEC / 1000) << " ms" << endl;
}




void crypto_exercise_test(int num, bool test){
	cout << "\t" << "Exercise " << num << ":\t";

	if(test)
	{
		cout << "[PASSED]" << endl;
	}
	else{
		cout << "[FAILED]" << endl;
	}
}




int main(int argc, char* argv[])
{
	/* Set 1 */
	// notation conversion testing
//	{
//		CR_str unknown_string = CR_str("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
//										CR_str::BASE64_ENCODED);
//
//		CR_str test = CR_str(unknown_string.as_ascii(), CR_str::ASCII_ENCODED);
//		cout << test.as_base64() << endl;
//	}


	/* Set 2 */
	cout << ">> Now testing: Set 2" << endl;

	/* Exercise 9 */
	tick();
	{
		static CR_str output = "YELLOW SUBMARINE\x04\x04\x04\x04";

		CR_str message = CR_str("YELLOW SUBMARINE");

		crypto_exercise_test(9,
					output == message.add_padding(CR_str::PKCS7_PADDING, 20)
				);

	};
	tock();

	/* Exercise 10 */
	tick();
	{
		static CR_str output =
			"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \n"
			"And I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \n"
			"Spaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n"
			"'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\n"
			"Play that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

		string line;
		string base64_encoded = string("");
		string key = string("YELLOW SUBMARINE");

		string IV = string();
		IV.resize(AES::BLOCKSIZE, 0); // size 16 - IV is all zeroes!

		ifstream string_file("encoded_ex10.txt");

		// read string into vector from file
		if (string_file.is_open()){
			while( getline(string_file, line) ){
				base64_encoded += line;
			}
			string_file.close();
		}
		else{
			cout << "Unable to open file" << endl;
		}

		CR_str ascii_encoded = CR_str( base64_encoded, CR_str::BASE64_ENCODED );
		CR_str message = CBC_AES_decrypt(ascii_encoded, key, IV);

		crypto_exercise_test(10,
					output == message.remove_padding(CR_str::UNKNOWN_PADDING)
				);

	};
	tock();

	/* Exercise 11 */
	cout << "\t" << "Exercise 11:\t";

	tick();
	{
		CR_str::EncryptionType encryption_type = detect_ECB_or_CBC_encryption(encrypt_using_CBC_or_ECB);

		if(encryption_type == CR_str::CBC_ENCRYPTION){
			cout << "Detected CBC encryption" << endl;
		}else if(encryption_type == CR_str::ECB_ENCRYPTION){
			cout << "Detected ECB encryption" << endl;
		}
		else{
			cout << "Encryption not recognized!" << endl;
		}

	}
	tock();

	/* Exercise 12 */
	tick();
	{

		static CR_str output =
				"Rollin' in my 5.0\n"
				"With my rag-top down so my hair can blow\n"
				"The girlies on standby waving just to say hi\n"
				"Did you stop? No, I just drove by\n";


		crypto_exercise_test(12,
					output == byte_at_a_time_ECB_decrypt_simple().remove_padding(CR_str::UNKNOWN_PADDING)
				);

	};
	tock();

	/* Exercise 13 */
	// TODO: finish this exercise
	tick();
	{
		static CR_str output = "email=blake@google.com*role*admin&role=user&uid=10";
		CR_str hacked_cookie = ecb_cut_and_paste();

		crypto_exercise_test(13,
					output == hacked_cookie.as_ascii()
				);

	};
	tock();

	/* Exercise 14 */
//	tick();
//	{
//		static CR_str output =
//				"Rollin' in my 5.0\n"
//				"With my rag-top down so my hair can blow\n"
//				"The girlies on standby waving just to say hi\n"
//				"Did you stop? No, I just drove by\n";
//
//		crypto_exercise_test(14,
//					output == byte_at_a_time_ECB_decrypt_hard().remove_padding(CR_str::UNKNOWN_PADDING)
//				);
//
//	};
//	tock();

	/* Exercise 15 */
	tick();
	{
		CR_str teststr1("ICE ICE BABY\x04\x04\x04\x04");
		CR_str teststr2("ICE ICE BABY\x05\x05\x05\x05");
		CR_str teststr3("ICE ICE BABY\x01\x02\x03\x04");

		crypto_exercise_test(15,
					teststr1.find_padding_type() == CR_str::PKCS7_PADDING and
					teststr2.find_padding_type() == CR_str::UNKNOWN_PADDING and
					teststr3.find_padding_type() == CR_str::UNKNOWN_PADDING
				);

	};
	tock();


	/* Exercise 16 */
	/* 	CBC bitflipping attacks */
	tick();
	{
		// generate unknown key only once
		static CR_str random_key = generate_random_AES_key(AES::BLOCKSIZE);
		// generate unknown IV only once
		static CR_str rand_IV = generate_random_AES_IV(AES::BLOCKSIZE);
		// create unknown string once
		static CR_str unknown_string = CR_str("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
													"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
													"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
													"YnkK", CR_str::BASE64_ENCODED);

		static CR_str prefix = "comment1=cooking%20MCs;userdata=";
		static CR_str suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
		static string output_token = ";admin=true;";

		CR_str message = "XXXXXXXXXXXXXXXX:admin<true:XXXX";
		CR_str encrypted = CBC_AES_encrypt(prefix + message + suffix, random_key, rand_IV);

		encrypted[32] ^= 1;
		encrypted[38] ^= 1;
		encrypted[43] ^= 1;

		CR_str decrypted = CBC_AES_decrypt(encrypted, random_key, rand_IV);
		decrypted = decrypted.remove_padding(CR_str::UNKNOWN_PADDING);

		crypto_exercise_test(16,
					decrypted.as_ascii().find(output_token) != std::string::npos
				);
	}
	tock();




	/* Set 3 */
//	cout << ">> Now testing: Set 3" << endl;
//
//	tick();
//	{
//		CR_str encrypted = CR_str("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qv"
//								"Y/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
//								CR_str::BASE64_ENCODED);
//		CR_str key = "YELLOW SUBMARINE";
//
//		cout << encrypted.as_base64() << endl;
//
//		CR_str nonce;
//		nonce.resize(AES::CTR_NONCE_SIZE, 0); // size 8 - nonce is all zeroes!
//
//		CR_str decrypted = CTR_AES_decrypt(encrypted, key, nonce);
//
//		cout << decrypted.as_ascii() << endl;
//	}
//	tock();

	return 0;
}

