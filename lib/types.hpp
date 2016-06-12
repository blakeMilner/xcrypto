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
	UKNOWN_ENCRYPTION
};


#endif /* LIB_TYPES_HPP_ */
