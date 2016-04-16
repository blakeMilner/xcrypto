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
	Xstr key;
	Xstr encoded_message;
} info_for_attacker;



string replace_str(string str, string oldStr, string newStr);

// Code for unique cookie functionality
map<Xstr, Xstr> parse_cookie(Xstr s);
Xstr compose_cookie(map<Xstr, Xstr> c);

Xstr profile_for(Xstr email);

info_for_attacker encrypt_cookie(Xstr cookie);
map<Xstr, Xstr> decrypt_cookie_and_parse(info_for_attacker info);

void print_cookie(map<Xstr, Xstr> cookie_dict);

Xstr ecb_cut_and_paste();


#endif
