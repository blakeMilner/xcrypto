#ifndef CODEC_HPP
#define CODEC_HPP

#include <iostream>
#include <cmath>
#include <algorithm>
#include <string>
#include <locale>
#include <limits>
#include <vector>
#include <utility>

#include <stdint.h>

using namespace std;


#define LC_TO_US_ADJUSTER 32
#define ASCII_MAX_VALUE 256

#define NUMBER_BASE64_CHARS 64
#define NUMBER_ASCII_CHARS 256

#define MIN_KEYSIZE 2
#define MAX_KEYSIZE 40

#define NUMBER_COMMON_CHARS 6
#define NUMBER_BASE64_CHARS 64



/* functions and tables related to encoding BASE64 */

extern const char common_chars_UC[NUMBER_COMMON_CHARS];

extern const char encoding_table[NUMBER_BASE64_CHARS];

static const char* BUILD_DECODING_TABLE() {
	char* table = (char*) malloc(NUMBER_ASCII_CHARS);

	for (int i = 0; i < NUMBER_BASE64_CHARS; i++)
		table[(unsigned char) encoding_table[i]] = i;

	return table;
}

extern const char* decoding_table;



// TODO: Store encoding representations (e.g. b64).
// make flag as to whether underlying ascii string has been altered.
// or store old ascii string along with encoded string, check old ascii == new

// TODO: reimplement using char[] - will this even be faster?

enum EncryptType {
	ECB_ENCRYPT,
	CBC_ENCRYPT,
	CTR_ENCRYPT,
	UKNOWN_ENCRYPTION
};
enum BlockSize {
	_4BYTE = 4, 	_8BYTE = 8, 	_16BYTE = 16,
	_32BYTE = 32, 	_64BYTE = 64,	_128BYTE = 128,
	_256BYTE = 256
};


class CR_Str {

public:
	enum PaddingType	{
			PKCS7_PADDING = '7',
			ZERO_PADDING = '0',
			UNKNOWN_PADDING = 'U',
			NO_PADDING = 'N'
			};

	enum EncodeType { ASCII_ENCODED, BASE64_ENCODED, HEX_ENCODED };

	/* Constructors / Destructor */
	CR_Str();
    CR_Str(const CR_Str&); // copy constructor for CR_string
    CR_Str(const char*); // copy constructor for C-style char*
	CR_Str(uint64_t); // for when a string is to be extracted from string binary
	CR_Str(string); // assume lone string is in ascii
	CR_Str(string, EncodeType); // user specifies type
	virtual ~CR_Str();

	// std::string functions that must be implemented
	size_t size();
	void resize(size_t new_size, char value);
	CR_Str substr(unsigned int position, size_t size);
	const char* c_str();
	void fill(const size_t s, const char& val);

	bool empty();

	/* members that return a raw std::string in a specific encoding */
	string as_ascii();
	string as_hex();
	string as_base64();
	string as_encoded(EncodeType format); // general case where the user inputs desired encoding format
	uint64_t as_int();

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

	/* mathematical operations for string */
	int hamming_distance(CR_Str string2);
	int rank_message_using_common_chars();
	void increment(int step = 1);
	void decrement(int step = -1);
	CR_Str XOR(CR_Str xor_str);
	CR_Str embed_string(CR_Str substring, int position, int bytes);
	CR_Str little_endian();

	/* block-wise operations */
		// block_num starts at 0

	// TODO: since blocksize is now set internally, remove all these block size parameters

	int get_num_blocks(int block_size);
	CR_Str get_single_block(int block_num, int block_size);
	CR_Str embed_single_block(CR_Str str, int block_num, int block_size);
	CR_Str get_multiple_block(int start_block_num, int end_block_num, int block_size);
	CR_Str embed_multiple_block(CR_Str str, int block_idx, int num_blocks, int block_size);

	/* functions related to padding */
	CR_Str add_padding(PaddingType type, int num_bytes);
	CR_Str remove_padding(PaddingType type);
	PaddingType find_padding_type();

	string pretty(EncodeType encoding = BASE64_ENCODED);

	/* Overloaded operators */

    char& operator[](int i);
    // Addition operator (+) for CR_string
    CR_Str operator+(const CR_Str& x);
    // Addition operator (+) for string
    CR_Str operator+(const string& x);
    // Addition operator (+) for char or int
    CR_Str operator+(const char& x);
    // XOR operator - forward to ::XOR function
    CR_Str operator^(const CR_Str& x);
    CR_Str operator+=(const CR_Str& x);
    CR_Str operator+=(const string& x);
    CR_Str operator+=(const char& x);

    // ostream << operator
    friend ostream& operator<<(ostream& os, const CR_Str& str);
    
    /* Binary comparison operators - should be friends since they need access
     * to ascii_string */
    friend bool operator==(const CR_Str& lhs, const CR_Str& rhs);
    friend bool operator!=(const CR_Str& lhs, const CR_Str& rhs);
    friend bool operator< (const CR_Str& lhs, const CR_Str& rhs);
    friend bool operator> (const CR_Str& lhs, const CR_Str& rhs);
    friend bool operator<=(const CR_Str& lhs, const CR_Str& rhs);
    friend bool operator>=(const CR_Str& lhs, const CR_Str& rhs);

    /* increment/decrement operators */
    CR_Str& operator++( );      // Prefix increment
    CR_Str operator++( int ); // Postfix increment
    CR_Str& operator--( );      // Prefix decrement
    CR_Str operator--( int ); // Postfix decrement


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
inline bool operator==(const CR_Str& lhs, const CR_Str& rhs){
	return (lhs.ascii_str == rhs.ascii_str);
}
inline bool operator!=(const CR_Str& lhs, const CR_Str& rhs){
	return (lhs.ascii_str != rhs.ascii_str);
}
inline bool operator< (const CR_Str& lhs, const CR_Str& rhs){
	return (lhs.ascii_str <  rhs.ascii_str);
}
inline bool operator> (const CR_Str& lhs, const CR_Str& rhs){
	return (lhs.ascii_str >  rhs.ascii_str);
}
inline bool operator<=(const CR_Str& lhs, const CR_Str& rhs){
	return (lhs.ascii_str <= rhs.ascii_str);
}
inline bool operator>=(const CR_Str& lhs, const CR_Str& rhs){
	return (lhs.ascii_str >= rhs.ascii_str);
}

inline char& CR_Str::operator[](int i)
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
inline  CR_Str CR_Str::operator+(const CR_Str& x)
 {
 	return CR_Str(this->ascii_str + x.ascii_str);
 }

 // Addition operator (+) for string
inline CR_Str CR_Str::operator+(const string& x)
 {
 	return CR_Str(this->ascii_str + x);
 }

 // Addition operator (+) for char or int
inline CR_Str CR_Str::operator+(const char& x)
 {
 	return CR_Str(this->ascii_str + x);
 }

 // XOR operator - forward to ::XOR function
inline CR_Str CR_Str::operator^(const CR_Str& x)
 {
 	return this->XOR(x);
 }

inline CR_Str CR_Str::operator+=(const CR_Str& x)
{
	*this = *this + x;

	return *this;
}

inline CR_Str CR_Str::operator+=(const string& x)
{
	this->ascii_str = this->ascii_str + x;

	return *this;
}

inline CR_Str CR_Str::operator+=(const char& x)
{
	this->ascii_str += string(1, x);

	return *this;
}

// Define prefix increment operator.
inline CR_Str& CR_Str::operator++(  )
{
	this->increment();
	return *this;
}

// Define postfix increment operator.
inline CR_Str CR_Str::operator++( int )
{
   CR_Str temp = *this;
   this->increment();
   return temp;
}

// Define prefix decrement operator.
inline CR_Str& CR_Str::operator--(  )
{
   this->decrement();
   return *this;
}

// Define postfix decrement operator.
inline CR_Str CR_Str::operator--( int )
{
   CR_Str temp = *this;
   this->decrement();
   return temp;
}


 // WATCH OUT FOR THIS, COUDL NEED
 // ostream << operator
inline ostream& operator<<(ostream& os, const CR_Str& str)
	{
		os << str.ascii_str;

	    return os;
	}



/* OTHER FUNCTIONS AND STRUCTURES */

typedef struct {
	CR_Str decoded;
	CR_Str key;
	bool key_found;
	int score;
} decoded_message;

decoded_message solve_single_byte_xor(CR_Str encoded);
decoded_message solve_repeating_key_xor(CR_Str encoded);


#endif
