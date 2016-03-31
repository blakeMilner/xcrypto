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
	CR_str key;
	CR_str encoded_message;
} info_for_attacker;



string replace_str(string str, string oldStr, string newStr);

// Code for unique cookie functionality
map<CR_str, CR_str> parse_cookie(CR_str s);
CR_str compose_cookie(map<CR_str, CR_str> c);

CR_str profile_for(CR_str email);

info_for_attacker encrypt_cookie(CR_str cookie);
map<CR_str, CR_str> decrypt_cookie_and_parse(info_for_attacker info);

void print_cookie(map<CR_str, CR_str> cookie_dict);

CR_str ecb_cut_and_paste();


#endif
