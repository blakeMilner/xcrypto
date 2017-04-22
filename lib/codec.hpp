#ifndef CODEC_HPP
#define CODEC_HPP

#include <iostream>
#include <sstream>
#include <string>
#include <cmath>
#include <algorithm>
#include <locale>
#include <limits>
#include <vector>
#include <utility>

#include <stdint.h>

#include "types.hpp"

using namespace std;


/* functions and tables related to encoding BASE64 */

extern const char common_chars_UC[_CONST::NUM_COMMON_CHARS];

extern const char encoding_table[_CONST::NUM_BASE64_CHARS];

static const char* BUILD_DECODING_TABLE() {
	char* table = (char*) malloc(_CONST::NUMBER_ASCII_CHARS * sizeof(char));

	// initialize with INVALID_CHAR so we can quickly figure out
	// if a user-supplied base64 char is invalid
	for(int i = 0; i < _CONST::NUMBER_ASCII_CHARS; i++){
		table[i] = _CONST::INVALID_BASE64_CHAR;
	}

	// make placeholder char (=) the same as the b64 char 'A', which is 0
	table[(unsigned char) '='] = 0;

	// build table
	for (int i = 0; i < _CONST::NUM_BASE64_CHARS; i++)
		table[(unsigned char) encoding_table[i]] = i;


	return table;
}

extern const char* decoding_table;



// TODO: reimplement using char[] - will this even be faster?

// TODO: in the future maybe make encoding finder function that tests to see if
// all characters are within a range , e.g. all chars are in the base64 char set
// could passing strings to functions without specifying encoding type

class Xstr {

public:
	enum PaddingType	{
			PKCS7_PADDING 	= '7',
			ZERO_PADDING 	= '0',
			UNKNOWN_PADDING = 'U',
			NO_PADDING 		= 'N'
			};

	// TODO: add base32?
	enum EncodeType { ASCII_ENCODED, BASE64_ENCODED, HEX_ENCODED, UNKNOWN_ENCODING };

	/* Constructors / Destructor */
	Xstr();
    Xstr(const Xstr&); // copy constructor for CR_string
    Xstr(const char*); // copy constructor for C-style char*
	Xstr(uint64_t); // form string based on binary representation of of int
	Xstr(int); // more limited case of previous constructor
	/* TODO: Make function that guesses encoding type */
	/* TODO: Make sure no input values to b64toascii and others aren't out of range */
	Xstr(string); // assume lone string is in ascii
	Xstr(string, EncodeType); // user specifies type
	Xstr(size_t n, char c);
	virtual ~Xstr();

	// std::string functions that must be implemented
	size_t size();
	void resize(size_t new_size, char value);
	void resize(size_t new_size);
	Xstr substr(unsigned int position, size_t size);
	const char* c_str();
	void fill(const size_t s, const char& val);

	bool empty();

	/* members that return a raw std::string in a specific encoding */
	string as_ascii();
	string as_hex();
	string as_base64();
	string as_encoded(EncodeType format); // general case where the user inputs desired encoding format
	uint64_t as_decimal();
	string as_int_string();

	/* static helper functions that convert between different encoding types */
	uint32_t hex_char_to_int(char hex);
	char int_to_hex_char(uint32_t int_c);
	string hex_to_ascii(string data);
	string ascii_to_hex(string data);
	string base64_to_ascii(string base64);
	string hex_to_base64(string data);
	string ascii_to_base64(string data);
	uint64_t ascii_to_int(string input);
	string int_to_ascii(uint64_t input);
	string int_to_binary(uint64_t input);

	/* mathematical operations for string */
	int hamming_distance(Xstr string2);
	int get_num_english_characters();
	void increment(int step = 1);
	void decrement(int step = -1);
	Xstr XOR(Xstr xor_str);
	Xstr XOR_wraparound(Xstr xor_str);
	Xstr embed_string(Xstr substring, int position, int bytes);
	Xstr little_endian();

	/* block-wise operations */
	// block_num starts at 0
	int get_num_blocks();
	Xstr get_single_block(int block_num);
	Xstr embed_single_block(Xstr str, int block_num);
	Xstr get_multiple_block(int start_block_num, int end_block_num);
	Xstr embed_multiple_block(Xstr str, int block_idx, int num_blocks);

	/* functions related to padding */
	Xstr add_padding(PaddingType type, int num_bytes = -1);
	Xstr remove_padding(PaddingType type);
	PaddingType find_padding_type();

	string pretty(EncodeType encoding = BASE64_ENCODED);

	char begin();
	char end();

	/* Overloaded operators */

	// Copy assignment operator
//    Xstr& operator= (const Xstr& other);

    // array access operator
    char& operator[](int i);
    // Addition operator (+) for CR_string
    Xstr operator+(const Xstr& x);
    // Addition operator (+) for string
    Xstr operator+(const string& x);
    // Addition operator (+) for char or int
    Xstr operator+(const char& x);
    // XOR operator - forward to ::XOR function
    Xstr operator^(const Xstr& x);
    Xstr operator+=(const Xstr& x);
    Xstr operator+=(const string& x);
    Xstr operator+=(const char& x);

    // ostream << operator
    friend ostream& operator<<(ostream& os, const Xstr& str);
    
    /* Binary comparison operators - should be friends since they need access
     * to ascii_string */
    friend bool operator==(const Xstr& lhs, const Xstr& rhs);
    friend bool operator!=(const Xstr& lhs, const Xstr& rhs);
    friend bool operator< (const Xstr& lhs, const Xstr& rhs);
    friend bool operator> (const Xstr& lhs, const Xstr& rhs);
    friend bool operator<=(const Xstr& lhs, const Xstr& rhs);
    friend bool operator>=(const Xstr& lhs, const Xstr& rhs);

    /* increment/decrement operators */
    Xstr& operator++( );      // Prefix increment
    Xstr operator++( int ); // Postfix increment
    Xstr& operator--( );      // Prefix decrement
    Xstr operator--( int ); // Postfix decrement


private:
	// assuming that strings are stored in big endian order
	string ascii_str;

	// attributes
	PaddingType padding = PaddingType::UNKNOWN_PADDING;
	EncryptType encryption = EncryptType::UKNOWN_ENCRYPTION;
	EncodeType encoding = EncodeType::ASCII_ENCODED;
	BlockSize blksz = BlockSize::_16BYTE;
};



/* Binary comparison operators - should be implemented as non-member functions */
inline bool operator==(const Xstr& lhs, const Xstr& rhs){
	return (lhs.ascii_str == rhs.ascii_str);
}
inline bool operator!=(const Xstr& lhs, const Xstr& rhs){
	return (lhs.ascii_str != rhs.ascii_str);
}
inline bool operator< (const Xstr& lhs, const Xstr& rhs){
	return (lhs.ascii_str <  rhs.ascii_str);
}
inline bool operator> (const Xstr& lhs, const Xstr& rhs){
	return (lhs.ascii_str >  rhs.ascii_str);
}
inline bool operator<=(const Xstr& lhs, const Xstr& rhs){
	return (lhs.ascii_str <= rhs.ascii_str);
}
inline bool operator>=(const Xstr& lhs, const Xstr& rhs){
	return (lhs.ascii_str >= rhs.ascii_str);
}



// Copy assignment operator
//inline Xstr& Xstr::operator= (const Xstr& other)
//{
//    Xstr tmp(other);         // re-use copy-constructor
//    *this = std::move(tmp); // re-use move-assignment
//    return *this;
//}

inline char& Xstr::operator[](int i)
 {
     if( i >= ascii_str.size() )
     {
         cout << "CR_String[]: Index out of bounds - too large." << endl;
         // return first element.
         return ascii_str[ ascii_str.size() - 1] ;
     }
     else if( i < 0 )
		{
			cout << "CR_String[]: Index out of bounds - less than zero" << endl;
			// return first element.
			return ascii_str[ 0 ];
		}

     return ascii_str[i];
 }

 // Addition operator (+) for CR_string
inline  Xstr Xstr::operator+(const Xstr& x)
 {
 	return Xstr(this->ascii_str + x.ascii_str);
 }

 // Addition operator (+) for string
inline Xstr Xstr::operator+(const string& x)
 {
 	return Xstr(this->ascii_str + x);
 }

 // Addition operator (+) for char or int
inline Xstr Xstr::operator+(const char& x)
 {
 	return Xstr(this->ascii_str + x);
 }

 // XOR operator - forward to ::XOR function
inline Xstr Xstr::operator^(const Xstr& x)
 {
 	return this->XOR(x);
 }

inline Xstr Xstr::operator+=(const Xstr& x)
{
	*this = *this + x;

	return *this;
}

inline Xstr Xstr::operator+=(const string& x)
{
	this->ascii_str = this->ascii_str + x;

	return *this;
}

inline Xstr Xstr::operator+=(const char& x)
{
	this->ascii_str += string(1, x);

	return *this;
}

// Define prefix increment operator.
inline Xstr& Xstr::operator++(  )
{
	this->increment();
	return *this;
}

// Define postfix increment operator.
inline Xstr Xstr::operator++( int )
{
   Xstr temp = *this;
   this->increment();
   return temp;
}

// Define prefix decrement operator.
inline Xstr& Xstr::operator--(  )
{
   this->decrement();
   return *this;
}

// Define postfix decrement operator.
inline Xstr Xstr::operator--( int )
{
   Xstr temp = *this;
   this->decrement();
   return temp;
}


 // WATCH OUT FOR THIS, COUDL NEED
 // ostream << operator
inline ostream& operator<<(ostream& os, const Xstr& str)
	{
		os << str.ascii_str;

	    return os;
	}



/* OTHER HELPER FUNCTIONS AND STRUCTURES */

typedef struct {
	Xstr decoded;
	Xstr key;
	bool key_found;
	int score;
} decoded_message;

decoded_message solve_single_byte_xor(Xstr encoded);
decoded_message solve_repeating_key_xor(Xstr encoded);
decoded_message solve_repeating_key_xor_2(Xstr encoded, int keysize);

bool contains_space_xor_with_special(char ch);
bool is_english_character(char ch);
Xstr::EncodeType find_encoding_type(string input);

#endif
