/*
 * cookie.hpp
 *
 *  Created on: Mar 26, 2016
 *      Author: blake
 */
#ifndef COOKIE_HPP
#define COOKIE_HPP

#include "codec.hpp"
#include "block_cipher.hpp"

#include <map>
#include <vector>

using namespace std;

typedef struct{
	CR_Str key;
	CR_Str encoded_message;
} info_for_attacker;



string replace_str(string str, string oldStr, string newStr);

// Code for unique cookie functionality
map<CR_Str, CR_Str> parse_cookie(CR_Str s);
CR_Str compose_cookie(map<CR_Str, CR_Str> c);

CR_Str profile_for(CR_Str email);

info_for_attacker encrypt_cookie(CR_Str cookie);
map<CR_Str, CR_Str> decrypt_cookie_and_parse(info_for_attacker info);

void print_cookie(map<CR_Str, CR_Str> cookie_dict);

CR_Str ecb_cut_and_paste();


#endif
