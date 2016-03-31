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




// TODO: reimplement using char[] - will this even be faster?

// TODO: possible add encryption attribute? if we don't know encryption then it could be specified as unknown or none...
// we could possible make encrypted_string class that inherits from this class

// TODO: add internal block size, instead of just default 16

// TODO: add attribute: contains_padding

// TODO: make option to print pretty


class CR_str {

public:
	enum PaddingType	{
			PKCS7_PADDING = '7',
			ZERO_PADDING = '0',
			UNKNOWN_PADDING = 'U',
			NO_PADDING = 'N'
			};

	enum EncryptionType { ECB_ENCRYPTION, CBC_ENCRYPTION, UKNOWN_ENCRYPTION };

	enum EncodingType { ASCII_ENCODED, BASE64_ENCODED, HEX_ENCODED };

	enum BlockSize {_4BYTE = 4, 	_8BYTE = 8, 	_16BYTE = 16,
					_32BYTE = 32, 	_64BYTE = 64,	_128BYTE = 128,
					_256BYTE = 256};


	/* Constructors / Destructor */
	CR_str();
    CR_str(const CR_str&); // copy constructor for CR_string
    CR_str(const char*); // copy constructor for C-style char*
	CR_str(uint64_t); // for when a string is to be extracted from string binary
	CR_str(string); // assume lone string is in ascii
	CR_str(string, EncodingType); // user specifies type
	virtual ~CR_str();

	// std::string functions that must be implemented
	size_t size();
	void resize(size_t new_size, char value);
	CR_str substr(unsigned int position, size_t size);
	const char* c_str();
	void fill(const size_t s, const char& val);

	/* members that return a raw std::string in a specific encoding */
	string as_ascii();
	string as_hex();
	string as_base64();
	string as_encoded(EncodingType format); // general case where the user inputs desired encoding format
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
	int hamming_distance(CR_str string2);
	int rank_message_using_common_chars();
	void increment(int step = 1);
	void decrement(int step = -1);
	CR_str XOR(CR_str xor_str);
	CR_str embed_string(CR_str substring, int position, int bytes);
	CR_str little_endian();

	/* block-wise operations */
		// block_num starts at 0
	int get_num_blocks(int block_size);
	CR_str get_single_block(int block_num, int block_size); 
	CR_str embed_single_block(CR_str str, int block_num, int block_size); 
	CR_str get_multiple_block(int start_block_num, int end_block_num, int block_size); 
	// TODO: implement this:
	// TODO: CR_string embed_multiple_block(CR_string str, int block_num, int block_size);

	/* functions related to padding */
	CR_str add_padding(PaddingType type, int num_bytes);
	CR_str remove_padding(PaddingType type);
	PaddingType find_padding_type();

	/* Overloaded operators */

	// TODO: make operators for string + CR_string

    char& operator[](int i)
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
    CR_str operator+(const CR_str& x)
    {
    	return CR_str(this->ascii_str + x.ascii_str);
    }

    // Addition operator (+) for string
    CR_str operator+(const string& x)
    {
    	return CR_str(this->ascii_str + x);
    }

    // Addition operator (+) for char or int
    CR_str operator+(const char& x)
    {
    	return CR_str(this->ascii_str + x);
    }

    // XOR operator - forward to ::XOR function
    CR_str operator^(const CR_str& x)
    {
    	return this->XOR(x);
    }

    CR_str operator+=(const CR_str& x)
	{
    	*this = *this + x;

    	return *this;
	}

    CR_str operator+=(const string& x)
	{
    	this->ascii_str = this->ascii_str + x;

    	return *this;
	}

    CR_str operator+=(const char& x)
	{
    	this->ascii_str += string(1, x);

//    	cout << "HERE" << endl;

    	return *this;
	}

    // ostream << operator
    friend ostream& operator<<(ostream& os, const CR_str& str)
	{
		os << str.ascii_str;

	    return os;
	}
    
    // TODO: add printing option where different blocks are displated separately

    /* Binary comparison operators - should be friends since they need access
     * to ascii_string */
    friend bool operator==(const CR_str& lhs, const CR_str& rhs);
    friend bool operator!=(const CR_str& lhs, const CR_str& rhs);
    friend bool operator< (const CR_str& lhs, const CR_str& rhs);
    friend bool operator> (const CR_str& lhs, const CR_str& rhs);
    friend bool operator<=(const CR_str& lhs, const CR_str& rhs);
    friend bool operator>=(const CR_str& lhs, const CR_str& rhs);


private:
	// assuming that strings are stored in big endian order
	string ascii_str;

	// attributes
	PaddingType padding = PaddingType::UNKNOWN_PADDING;
	EncryptionType encryption = EncryptionType::UKNOWN_ENCRYPTION;
	EncodingType encoding = EncodingType::ASCII_ENCODED;
	BlockSize blksz = BlockSize::_16BYTE;
};

/* Binary comparison operators - should be implemented as non-member functions */
inline bool operator==(const CR_str& lhs, const CR_str& rhs){
	return (lhs.ascii_str == rhs.ascii_str);
}
inline bool operator!=(const CR_str& lhs, const CR_str& rhs){
	return (lhs.ascii_str != rhs.ascii_str);
}
inline bool operator< (const CR_str& lhs, const CR_str& rhs){
	return (lhs.ascii_str <  rhs.ascii_str);
}
inline bool operator> (const CR_str& lhs, const CR_str& rhs){
	return (lhs.ascii_str >  rhs.ascii_str);
}
inline bool operator<=(const CR_str& lhs, const CR_str& rhs){
	return (lhs.ascii_str <= rhs.ascii_str);
}
inline bool operator>=(const CR_str& lhs, const CR_str& rhs){
	return (lhs.ascii_str >= rhs.ascii_str);
}


/* OTHER FUNCTIONS AND STRUCTURES */

typedef struct {
	CR_str decoded;
	CR_str key;
	bool key_found;
	int score;
} decoded_message;

decoded_message solve_single_byte_xor(CR_str encoded);
decoded_message solve_repeating_key_xor(CR_str encoded);


#endif
