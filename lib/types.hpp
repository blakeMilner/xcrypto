/*
 * types.hpp
 *
 *  Created on: Jun 12, 2016
 *      Author: blake
 */

#ifndef LIB_TYPES_HPP_
#define LIB_TYPES_HPP_


// TODO: refactor all uint8_t as uint8
typedef uint8_t uint8;

// constants related to encoding and settings
namespace _CONST{
	const int NUM_BASE64_CHARS = 64;
	const int NUMBER_ASCII_CHARS = 256;

	const int MIN_XOR_KEYSIZE = 2;
	const int MAX_XOR_KEYSIZE = 40;

	const int NUM_COMMON_CHARS = 6;

	const char INVALID_BASE64_CHAR = (char) 255;
}

enum BlockSize {
	_4BYTE = 4, 	_8BYTE = 8, 	_16BYTE = 16,
	_32BYTE = 32, 	_64BYTE = 64,	_128BYTE = 128,
	_256BYTE = 256
};

enum CipherType {
	AES,
	DES
};

enum EncryptType {
	ECB_ENCRYPT,
	CBC_ENCRYPT,
	CTR_ENCRYPT,
	MT19937_ENCRYPT,
	UKNOWN_ENCRYPTION
};


#endif /* LIB_TYPES_HPP_ */
