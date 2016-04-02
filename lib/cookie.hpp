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
	XStr key;
	XStr encoded_message;
} info_for_attacker;



string replace_str(string str, string oldStr, string newStr);

// Code for unique cookie functionality
map<XStr, XStr> parse_cookie(XStr s);
XStr compose_cookie(map<XStr, XStr> c);

XStr profile_for(XStr email);

info_for_attacker encrypt_cookie(XStr cookie);
map<XStr, XStr> decrypt_cookie_and_parse(info_for_attacker info);

void print_cookie(map<XStr, XStr> cookie_dict);

XStr ecb_cut_and_paste();


#endif
