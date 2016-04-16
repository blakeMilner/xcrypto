/*
 * cookie.cpp
 *
 *  Created on: Mar 26, 2016
 *      Author: blake
 */
#include "cookie.hpp"





// Code for unique cookie functionality
string replace_str(string str, string oldStr, string newStr){
	size_t pos = 0;
	while((pos = str.find(oldStr, pos)) != std::string::npos){
		str.replace(pos, oldStr.length(), newStr);
		pos += newStr.length();
	}

	return str;
}

map<Xstr, Xstr> parse_cookie(Xstr s){
        vector<char*> tokens = vector<char*>();
        map<Xstr, Xstr> dict = map<Xstr, Xstr>();

        // token string
        char *p = strtok((char*) s.c_str(), "&");

        while(p){
                tokens.push_back(p);
                p = strtok(NULL, "&");
        }

        // extract key/value for token
        for(vector<int>::size_type i = 0; i < tokens.size(); i++) {
                char *k = strtok(tokens[i], "=");
                char *v = strtok(NULL, "=");
                dict[k] = v;
        }

        return dict;
}

Xstr compose_cookie(map<Xstr, Xstr> c){
	Xstr cookie = Xstr();

	map<Xstr, Xstr>::iterator it = c.begin();
	while( true ){
		Xstr k = it->first;
		Xstr v = it->second;
		cookie += k + string("=") + v;

		// increment now so we can check if we're at the end before adding another &
		it++;
		if( it != c.end() ){
			cookie += string("&");
		}
		else{ // in this case we're done parsing.
			break;
		}
	}

	return cookie;
}

Xstr profile_for(Xstr email){
	map<Xstr, Xstr> dict;

	// remove illegal characters & and =
	// e.g. to prevent "foo@bar.com&role=admin".
	string old_email = email.as_ascii();
	email = replace_str(email.as_ascii(), "&", "");
	email = replace_str(email.as_ascii(), "=", "");

	if(email != old_email){
		//cout << "profile_for(): Illegal characters detected, "
		//		"removing and proceeding with profile creation." << endl;
	}

	// populate dictionary
	dict["email"] = email;
	dict["uid"] = "10";
	dict["role"] = "user";

	return compose_cookie(dict);
}

info_for_attacker encrypt_cookie(Xstr cookie){
	info_for_attacker info;

	info.key = generate_random_AES_key();
	info.encoded_message = BlockCipher::encrypt(EncryptType::ECB_ENCRYPT, cookie, info.key);

	return info;
}

map<Xstr, Xstr> decrypt_cookie_and_parse(info_for_attacker info){
	Xstr decrypted_cookie = BlockCipher::decrypt(EncryptType::ECB_ENCRYPT, info.encoded_message, info.key);

	return parse_cookie(decrypted_cookie);
}

void print_cookie(map<Xstr, Xstr> cookie_dict){
    cout << "Cookie contents: " << endl;

    for(map<Xstr, Xstr>::const_iterator it = cookie_dict.begin();
    		it != cookie_dict.end();
    		++it)
    {
        cout << "\t" << it->first << " = " << it->second << endl;
    }

    cout << endl;
}

Xstr ecb_cut_and_paste()
{
    Xstr email = "foo@bar.com&role=admin";

	// testing cookie composition and profile creation
    Xstr cookie = profile_for(email);

    //cout << "Cookie: " << cookie << endl;

    // testing cookie parsing
    map<Xstr, Xstr> cookie_dict = parse_cookie(cookie);
    //print_cookie(cookie_dict);

    // testing 2 encryption functions
    cookie = profile_for(email);
    info_for_attacker info = encrypt_cookie(cookie);
    //cout << "Original cookie: " << cookie.as_ascii() << endl;
    //cout << "Key provided to attacker: " << info.key.as_base64() << endl;
    //cout << "Encrypted message provided to attacker: " << info.encoded_message.as_base64() << endl;

    map<Xstr, Xstr> decrypted_cookie = decrypt_cookie_and_parse(info);
    //cout << "Decrypted cookie: " << endl;
    //print_cookie(decrypted_cookie);

    // attacker routines to tamper with cookie, allowing &role=admin
    Xstr dummy_email = "blake@google.com*role*admin"; // * characters will be replaced with & and =

    // NOTE: these both occur in block 1 - subtract block size to make relative to block 1
    int block_idx = 1;
    int idx_for_ampersand = 22 - (block_idx * 16);
    int idx_for_equals = 27 - (block_idx * 16);

    // create dummy cookie and then encrypt
    Xstr dummy_cookie = profile_for(dummy_email);
    info_for_attacker dummy_info = encrypt_cookie(dummy_cookie);

    //cout << dummy_cookie << endl;

    // get first block that contains dummy * characters
    Xstr block_to_replace = dummy_cookie.get_single_block(1);

    //cout << "btr: " << block_to_replace.as_ascii() << endl;
    //cout << dummy_cookie.get_single_block(2, 16) << endl;

    // replace dummy *'s  with forbidden & and =
    Xstr encrypted_block_to_replace = BlockCipher::encrypt(EncryptType::ECB_ENCRYPT, block_to_replace, info.key);
    //cout << encrypted_block_to_replace.size() << endl;

    // embed altered cipherblock into the encrypted cookie
//    cout << dummy_info.encoded_message.size() << endl;
    Xstr cut_and_pasted = dummy_info.encoded_message.embed_single_block(encrypted_block_to_replace, block_idx);

    // decrypt the cut and pasted cookie
    Xstr hacked_cookie = BlockCipher::decrypt(EncryptType::ECB_ENCRYPT, cut_and_pasted, info.key);
//    cout << hacked_cookie.as_ascii() << endl;

    return hacked_cookie;
}

