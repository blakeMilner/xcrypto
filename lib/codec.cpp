#include "codec.hpp"


/* tables for encoding */
const char common_chars_UC[NUMBER_COMMON_CHARS] =
		{'E','T','A','O','I','N'};

const char encoding_table[NUMBER_BASE64_CHARS] =
		{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '+', '/'};

const char* decoding_table = BUILD_DECODING_TABLE();






// TODO: put this somewhere else
int sign(int x) {
    return (x > 0) - (x < 0);
}






// if no arguments passed, make empty string
Xstr::Xstr():
	ascii_str("")
{
}

// copy constructor for CR_string
Xstr::Xstr(const Xstr& s){
	this->ascii_str = s.ascii_str;
}

// for when a string is to be extracted from string binary
Xstr::Xstr(uint64_t number){
	this->ascii_str = int_to_ascii(number);
}

// assume lone string is in ascii
Xstr::Xstr(string ascii_assumed){
	this->ascii_str = ascii_assumed;
}

// copy constructor for C-style char*
Xstr::Xstr(const char* s){
        *this = Xstr(string(s));
}

// user specifies type
Xstr::Xstr(string input, EncodeType encoding){
	switch(encoding){
		case Xstr::ASCII_ENCODED:
			this->ascii_str = input;
			break;

		case Xstr::BASE64_ENCODED:
			this->ascii_str = base64_to_ascii(input);
			break;

		case Xstr::HEX_ENCODED:
			this->ascii_str = hex_to_ascii(input);
			break;

		default:
			cout << "CR_string constructor: Invalid string encoding type " <<
					"specified, assuming ascii" << endl;

			this->ascii_str = input;

			break;
	}
}

Xstr::~Xstr(){
}

uint32_t Xstr::hex_char_to_int(char hex){
	if(hex >= 'A' and hex <= 'F'){
		return (hex - 55);
	}
	else if(hex >= 'a' and hex <= 'f'){
		return (hex - 87);
	}
	else if(hex >= '0' and hex <= '9'){
		return (hex - '0');
	}
	else{
		cout << "hex_char_to_int out of bounds: " << hex << endl;
		return 0;
	}
}

char Xstr::int_to_hex_char(uint32_t int_c){
	if(int_c >= 0 and int_c <= 9){
		return int_c + '0';
	}
	else if(int_c >= 10 and int_c <= 15){
		return int_c + 'A' - 10;
	}
	else{
		cout << "int_to_hex_char out of bounds: " << int_c << endl;
		return 0;
	}
}

string Xstr::hex_to_ascii(string data){
    int out_length = data.size() / 2;
    if (data[data.size() - 1] == '=') out_length--;

    string decoded_data = string();
    decoded_data.resize(out_length, 0);

    for (int i = 0, j = 0; i < (int) data.size(); i += 2) {
        if (j > out_length - 1) break;

        data[i] = hex_char_to_int(data[i]);
        data[i+1] = hex_char_to_int(data[i+1]);

        decoded_data[j++] = (data[i] << 4) + data[i+1];
    }

    return decoded_data;
}

string Xstr::ascii_to_hex(string data){
    int out_length = data.size() * 2;

    string decoded_data = string();
    decoded_data.resize(out_length, 0);

    for (int hex = 0, asc = 0; asc < (int) data.size(); hex += 2, asc += 1) {
        if (hex > out_length - 2) break;

    	// extract left and right nibbles from input ascii, make two hex chars
    	decoded_data[hex]   = (data[asc] & 0xF0) >> 4;
    	decoded_data[hex+1] = (data[asc] & 0x0F);

    	// convert from number to char
    	decoded_data[hex] =   int_to_hex_char(decoded_data[hex]);
    	decoded_data[hex+1] = int_to_hex_char(decoded_data[hex+1]);
    }

    return decoded_data;
}

// The return value of this function is good up to 2*16 bytes
// Strings that have 16 characters or under (aka have 16 bytes or less) will
// not overflow this structure. In these cases you can downcast (to smaller
// integers) at your discretion.
// Strings over 17 bytes will, however. In this case the 16 most significant bits will
// be returned.
uint64_t Xstr::ascii_to_int(string input){
	int num_bytes_to_extract = input.size();

	if(input.size() > this->blksz){
		cout << "ascii_to_int(): Input string is greater than "
				<< blksz + 1
				<< " bytes. Extracting the "
				<< blksz
				<< "most significant bytes" << endl;

		num_bytes_to_extract = blksz;
	}

	uint64_t accumulator = 0;

	// i is the shift counter - it starts out high since we are reading out
	// the most significant bits first
	int i = num_bytes_to_extract - 1;

	// go from end of string to (end - num_bytes_to_extract) position, extracting values
	for(int bit = input.size(); bit > input.size() - num_bytes_to_extract; bit--){

		// add weighted ascii character to the accumulator
		// multiply each character by (256^i), where "i" is the
		// NOTE: we need to cast to (unsigned char) because it is stored as
		// a (signed char).
		accumulator += ((unsigned char) input[bit - 1]) * pow(256, i);

		i--;
	}

	return accumulator;
}

// Likewise, this function can convert to ascii of up to 16 bytes
string Xstr::int_to_ascii(uint64_t input){
	// this is the number of output string characters we'll need
	// We're calculating log_256_(input)
	// rounding up gives us the number of bytes that will be used up
	int num_output_bytes_needed = (log(input) / log(256)) + 1;

	string output = string();
	output.resize(num_output_bytes_needed, 0);

	// go from end of string to (end - num_bytes_to_extract) position, extracting values
	for(int byte = num_output_bytes_needed - 1; byte >= 0; byte--){
		int output_byte = (input / pow(256, byte));

		// note: we are storing output_byte, which is an (unsigned char), as a
		// (signed char). This doesn't matter for string-string operations, but matters
		// when we are working with the raw value of the character within the string.
		// We'll need to adjust this in ascii_to_int();
		output[byte] = output_byte;

		// subtract off the output byte scaled by its digit position
		input -= (output_byte * pow(256, byte));
	}

	return output;
}

// TODO: implement changes in this section (accounting for remainder) into other functions)
// TODO: document why we use % 3 or % 4

string Xstr::ascii_to_base64(string input){
    int output_length = ceil((float) (input.size() * 4) / (float) 3);

    string encoded_data = string();
    encoded_data.resize(output_length, 0);

    int asc = 0;
    int b64 = 0;

   	if((input.size() % 3) == 1){
		uint8_t ascii_1 = input[asc    ];

		encoded_data[b64    ] = ((ascii_1 & 0b11111100) >> 2);
		encoded_data[b64 + 1] = ((ascii_1 & 0b00000011));

		encoded_data[b64    ] = encoding_table[ encoded_data[b64    ] ];
		encoded_data[b64 + 1] = encoding_table[ encoded_data[b64 + 1] ];

		asc = 1;
		b64 = 2;
	}
	else if((input.size() % 3) == 2){
		uint8_t ascii_1 = input[asc    ];
		uint8_t ascii_2 = input[asc + 1];

		encoded_data[b64    ] = ((ascii_1 & 0b11111100) >> 2);
		encoded_data[b64 + 1] = ((ascii_1 & 0b00000011) << 4) + ((ascii_2 & 0b11110000) >> 4);
		encoded_data[b64 + 2] = ((ascii_2 & 0b00001111));

		encoded_data[b64    ] = encoding_table[ encoded_data[b64    ] ];
		encoded_data[b64 + 1] = encoding_table[ encoded_data[b64 + 1] ];
		encoded_data[b64 + 2] = encoding_table[ encoded_data[b64 + 2] ];

		asc = 2;
		b64 = 3;
	}

    for (asc, b64; asc < input.size(); asc += 3, b64 += 4){
        uint8_t ascii_1 = input[asc    ];
        uint8_t ascii_2 = input[asc + 1];
        uint8_t ascii_3 = input[asc + 2];

        encoded_data[b64    ] = ((ascii_1 & 0b11111100) >> 2);
        encoded_data[b64 + 1] = ((ascii_1 & 0b00000011) << 4) + ((ascii_2 & 0b11110000) >> 4);
        encoded_data[b64 + 2] = ((ascii_2 & 0b00001111) << 2) + ((ascii_3 & 0b11000000) >> 6);
        encoded_data[b64 + 3] = ((ascii_3 & 0b00111111)     );

        encoded_data[b64    ] = encoding_table[ encoded_data[b64    ] ];
        encoded_data[b64 + 1] = encoding_table[ encoded_data[b64 + 1] ];
        encoded_data[b64 + 2] = encoding_table[ encoded_data[b64 + 2] ];
        encoded_data[b64 + 3] = encoding_table[ encoded_data[b64 + 3] ];
    }

    return encoded_data;
}

// TODO: URGENT: STILL LOSING CHARS AT THE END OF THE STRING...
// TDDO: check that number is valid Base64

string Xstr::base64_to_ascii(string input){
	int input_length = input.size();

    if (input[input.size() - 1] == '=') input_length--;
    if (input[input.size() - 2] == '=') input_length--;
    if (input[input.size() - 3] == '=') input_length--;

    int output_length = (float) (input_length * 3) / (float) 4;

    string decoded_data = string();
    decoded_data.resize(output_length, 0);

    for(int asc = 0, b64 = 0; b64 < (int) input.size(); asc += 3, b64 += 4){
        if (asc > output_length - 3) break;

        uint8_t base64_1 = decoding_table[ input[b64    ] ];
        uint8_t base64_2 = decoding_table[ input[b64 + 1] ];
        uint8_t base64_3 = decoding_table[ input[b64 + 2] ];
        uint8_t base64_4 = decoding_table[ input[b64 + 3] ];

        decoded_data[asc    ] = ((base64_1           ) << 2) + ((base64_2 & 0b110000) >> 4);
        decoded_data[asc + 1] = ((base64_2 & 0b001111) << 4) + ((base64_3 & 0b111100) >> 2);
        decoded_data[asc + 2] = ((base64_3 & 0b000011) << 6) + ((base64_4           )     );

//        cout << asc + 2 << endl;
    }

    return decoded_data;
}






string Xstr::as_ascii(){
	return ascii_str;
}

string Xstr::as_hex(){
	return ascii_to_hex(ascii_str);
}

string Xstr::as_base64(){
	return ascii_to_base64(ascii_str);
}

string Xstr::as_encoded(EncodeType format){
	switch(format){
		case Xstr::ASCII_ENCODED:
			return as_ascii();	
			break;
	
		case Xstr::BASE64_ENCODED:
			return as_base64();
			break;
	
		case Xstr::HEX_ENCODED:
			return as_hex();
			break;
	
		default:
			cout << "as_encoded(): input encoding format type not recognized. Default to base64." << endl;

			return as_base64();
			break;
	}
}

uint64_t Xstr::as_int(){
	return ascii_to_int(ascii_str);
}

string Xstr::as_int_string(){
	string output = string();

	for(int i = 0; i < ascii_str.size(); i++){
		int Number = (int) ascii_str[i];       // number to be converted to a string

		string Result;          // string which will contain the result
		ostringstream convert;   // stream used for the conversion

		convert << Number;      // insert the textual representation of 'Number' in the characters in the stream

		output += convert.str() + " ";
	}

	output.erase(output.size(), 1); // delete last character to remove extra " "

	return output;
}

// size of string in ascii representation
size_t Xstr::size(){
	return ascii_str.size();
}

// if the size decreases, all old data is left in there
// if size increases, new space is initialized with user supplied value
void Xstr::resize(size_t new_size, char value){
	ascii_str.resize(new_size, value);
}

void Xstr::resize(size_t new_size){
	ascii_str.resize(new_size);
}

Xstr Xstr::substr(unsigned int position, size_t size){
	return ascii_str.substr(position, size);
}

const char* Xstr::c_str(){
	return ascii_str.c_str();
}

// TODO: just make constructor with these params and fill by initializing
void Xstr::fill(const size_t s, const char& val){
	ascii_str = string(s, val); // create new string of length s
}

bool Xstr::empty(){
	return (this->size() == 0);
}

int Xstr::hamming_distance(Xstr string2){
	if(this->size() != string2.size()){
		cout << "hamming_distance(): strings are not equal lengths." << endl;

		return -1;
	}

	int distance = 0;

	// scan through each char, evaluating each bit with XOR
	for(int chr = 0; chr < this->size(); chr++){
		// produces bit sequence where 0 bits represent equal elements
		uint8_t val = (this->ascii_str)[chr] ^ string2[chr];

		// Wegner algorithm
		// counts 0, i.e. counts equal elements in bit sequences
		while(val)
		{
			distance++;
			val &= val - 1;
		}
	}

	// normalize the hamming distance by the length of the strings
	distance /= this->size();

	return distance;
}

int Xstr::get_num_english_characters(){
	int total = 0;

	for(int i = 0; i < ascii_str.size(); i++){
		char ch = ascii_str[i];

		if(
				(ch >= '0' && ch <= '9')
			|| (ch >= 'a' && ch <= 'z')
			|| (ch >= 'A' && ch <= 'Z')
			|| ch == ' ' || ch == '-' || ch == '\''
			|| ch == '\n' || ch == '/' || ch == ','
			|| ch == '.' || ch == '?')

		{
			total++;
		}
	}

	return total;
}

void Xstr::increment(int step /* = 1 */){
	uint8_t current_byte = 0;
	uint8_t carry_byte = 0;
	unsigned int current_idx = ascii_str.size() - 1;

	// Exit if there is no step
	// If we're postive stepping, then we want to carry when we hit the max (255)
	// Otherwise, we carry when we hit the min (0)
	if(step == 0){
		return;
	}
	if(step > 0){
		carry_byte = 255;
	}
	else if(step < 0){
		carry_byte = 0;
	}

	// if we execute this do-while loop more than once, then a wrap_around is occurring
	// We must carry the increment over to the more significant bytes.
	// If these bytes wrap around as well, then we keep propagating
	// We can purposefully overflow the bytes to set them back to 0.

	// might not work for decrements....

	do{
		current_byte = ascii_str[current_idx];
		ascii_str[current_idx] += step;

//		// for next carry rounds, make step = 1
//		if(current_idx == ascii_str.size() - 1)
//			step = sign(step);

		current_idx--;
	}
	while( (current_idx >= 0) and ((current_byte + step) > carry_byte) );

//	// detect overflow
//	if((current_idx == -1) && ()){
//
//	}

}

void Xstr::decrement(int step /* = -1 */){
	increment(step);
}

// TODO: make sure this won't mess up other code:
// e.g. if we expect to get a string that is sizeof(longer)
Xstr Xstr::XOR(Xstr xor_str){
	Xstr longer, shorter;

	if(this->size() > xor_str.size()){
		longer = *this;
		shorter = xor_str;
	}
	else{
		longer = xor_str;
		shorter = *this;
	}

	// when we get to the end of the shorter string, we just wrap around
	// and start back at the first character of the shorter string
	for(int i = 0; i < shorter.size(); i++){
		shorter[i] = longer[i] ^ shorter[i];
	}

	return shorter;
}

Xstr Xstr::embed_string(Xstr substring, int position, int bytes){
	Xstr new_string = this->ascii_str;

	int i = position;
	int j = 0;

	while(i < ascii_str.size() and j < bytes){
		new_string[i] = substring[j];

		i++;
		j++;
	}

	return new_string;
}

// return string in little endian order
// in other words: bit-flip the string!
Xstr Xstr::little_endian(){
	Xstr litend;

	for(int i = this->size() - 1; i >= 0; i--){
		litend += this->ascii_str[i];
	}

	return litend;
}

int Xstr::get_num_blocks(){
	if(blksz < 1){
		cout << "get_num_blocks(): block size is < 0." << endl;

		return 0;
	}

	return ceil((double) this->size() / (double) blksz);
}

// block_num starts from 0
Xstr Xstr::get_single_block(int block_num){
	if(block_num < 0){
		cout << "get_single_block(): block number is < 0." << endl;

		return Xstr();
	}

	return this->substr(block_num * blksz, blksz);
}

// block_num starts from 0
Xstr Xstr::embed_single_block(Xstr str, int block_idx){
	int start_pos = block_idx * blksz;
	
	if(block_idx < 0){
		cout << "embed_single_block(): block number is < 0." << endl;

		return Xstr();
	}
	
	if(this->size() < (start_pos + blksz)){
		cout << "embed_single_block(): WARNING: embedded string will overrun bounds, "
				"increasing string length by necessary size." << endl;
	}
	
	// TODO: figure our if string::replace will make size of string longer if we overrun bounds
	string old_str = this->as_ascii();
	old_str.replace(start_pos, blksz, str.as_ascii());

	return old_str;
}

// block_num starts from 0
Xstr Xstr::get_multiple_block(int start_block_num, int end_block_num){
	if(start_block_num < 0){
		cout << "get_multiple_block(): starting block number is < 0." << endl;

		return Xstr();
	}
	else if(end_block_num < 0){
		cout << "get_multiple_block(): ending block number is < 0." << endl;

		return Xstr();
	}
	else if(end_block_num < start_block_num){
		cout << "get_multiple_block(): ending block is before starting block." << endl;

		return Xstr();
	}

	int range_size = (end_block_num - start_block_num + 1) * blksz;

	return this->substr(start_block_num * blksz, range_size);
}

//
// TODO: untested as of yet
//
Xstr Xstr::embed_multiple_block(Xstr str, int block_idx, int num_blocks){
	int start_pos = block_idx * blksz;
	int block_length = (blksz * num_blocks);

	if(block_idx < 0){
		cout << "embed_multiple_block(): block number is < 0." << endl;

		return Xstr();
	}

	if(this->size() < (start_pos + block_length)){
		cout << "embed_multiple_block(): WARNING: embedded string will overrun bounds, "
				"increasing string length by necessary size." << endl;

		ascii_str.resize(start_pos + block_length, 0); // resize to new bound, fill with 0
	}

	string old_str = this->as_ascii();
	old_str.replace(start_pos, block_length, str.as_ascii());

	return old_str;
}

// add_padding will add padding characters until the string is divisible by block_size
// if the original string has size less than block_size, then we pad up to 1 block_size
Xstr Xstr::add_padding(PaddingType type, int desired_block_size /* = -1 */){
	Xstr padded_string = Xstr();
	Xstr prior_blocks = Xstr();

	// initial checks

	// if no block size provided, assume internal block size
	if(desired_block_size == -1){
		desired_block_size = blksz;
	}

	if(this->size() < 1){
		cout << "add_padding(): input padded_string size is less than 1. " <<
				"Must have at least 1 character in order for there to be padding"<< endl;

		return *this;
	}
	else if(desired_block_size < 2){
		cout << "add_padding(): input padded_string padding length is under 2 bytes." << endl;

		return *this;
	}

	// input padded_string is already even block size, return unchanged string
	if( (this->size() % desired_block_size) == 0 ){
		return *this;
	}

	// if we have a string that is greater than 1 block, strip out incomplete block and work on that
	// we will put this padded incomplete block at the end of the original sequence after padding
	if(this->size() > desired_block_size){
		int last_block_num = this->get_num_blocks() - 1;

		padded_string = get_single_block(last_block_num);


		prior_blocks = get_multiple_block(0, last_block_num - 1);
	}
	else{
		padded_string = *this;
		prior_blocks = Xstr("");
	}

	// given user-specified padding type, find value of pad bytes
	int pad_value = 0;

	switch(type){
		case Xstr::PKCS7_PADDING:
			pad_value = desired_block_size - padded_string.size();

			break;

		case Xstr::ZERO_PADDING:
			pad_value = 0;

			break;

		case Xstr::UNKNOWN_PADDING:
			pad_value = desired_block_size - padded_string.size(); // assume PKCS7 padding for unknown
			break;

		default:
			cout << "add_padding(): input padding type not recognized. Assuming PKCS7 padding." << endl;
			pad_value = desired_block_size - padded_string.size();

			break;
	}

	// do the padding
	int pad_length = desired_block_size - padded_string.size();

	for(int i = 0; i < pad_length; i++){
		padded_string += (char) pad_value;
		//cout << (int) pad_value << endl;
	}

	return ( prior_blocks + padded_string );
}

Xstr Xstr::remove_padding(PaddingType type){
	Xstr padded_string = this->ascii_str;

	if(padded_string.size() < 2){
		cout << "remove_padding(): input padded_string size is less than 2. " <<
				"Must have at least 2 characters in order for there to be padding" << endl;

		return *this;
	}

	// value that the paddings numbers will take
	int pad_value = 0;

	// check if the padding type is unknown
	if(type == Xstr::UNKNOWN_PADDING){
		if(padded_string.find_padding_type() == Xstr::PKCS7_PADDING){
			type = Xstr::PKCS7_PADDING;
		}
		else if(padded_string.find_padding_type() == Xstr::ZERO_PADDING){
			type = Xstr::ZERO_PADDING;
		}
		else{
			type = Xstr::UNKNOWN_PADDING;
		}
	}

	// given user-specified padding type, find value of pad bytes
	switch(type){
		case Xstr::PKCS7_PADDING:
			// if there is padding, the last character must represent
			// the value of the padding characters used
			pad_value = padded_string[padded_string.size() - 1];

			break;

		case Xstr::ZERO_PADDING:
			pad_value = 0;

			break;

		default:
			// assume no padding otherwise and return string
			return Xstr( padded_string );

			break;
	}

	// for the following routines, we try to detect suffixes that are strings of repeating
	// characters. The values of the individual characters are equal to the number of these characters.
	// We treat the case where a single value of 0x01 at the end of a string is padding

	int i = padded_string.size() - 1;
	char next_char = 0;

	do{
		next_char = padded_string[i];
		i--;
	}
	while(next_char == padded_string[i]);

	int padding_size = padded_string.size() - 1 - i;


	// if pkcs7 padding has been used, we expect the padding chars (sampled by
	// next_char) to have values specified by pad_value (depends on padding type)

	if(next_char == pad_value){
		Xstr stripped_padded_string = padded_string.substr(0, padded_string.size() - padding_size);

		return stripped_padded_string;
	}
	// else there is no padding
	else{
		return Xstr( padded_string );
	}
}

Xstr::PaddingType Xstr::find_padding_type(){
	string padded_string = this->ascii_str;

	if(padded_string.size() < 2){
		cout << "find_Attr::Padding_Type(): input padded_string size is less than 2. " <<
				"Must have at least 2 characters in order for there to be padding" << endl;

		return Xstr::NO_PADDING;
	}

	// if the last digit is 0, then that implies there must be 0 padding
	if(padded_string[padded_string.size() - 1] == 0){
//		cout << "EREURNIG  ZEOR" << endl << endl;

		return Xstr::ZERO_PADDING;
	}

	// set pkcs7 pad value to the last character in the string,
	// since it must contain the pad value
	const int pkcs7_pad_value = padded_string[padded_string.size() - 1];

//	cout << pkcs7_pad_value << endl;

	// for the following routines, we try to detect suffixes that are strings of repeating
	// characters. The values of the individual characters are equal to the number of these characters.
	// We treat the case where a single value of 0x01 at the end of a string is padding

//	cout << " == " << this->as_hex() << endl;

	int i = padded_string.size() - 1;
	char next_char = 0;

	do{
		next_char = padded_string[i];
		i--;
	}
	while(next_char == padded_string[i]);

	int padding_size = padded_string.size() - 1 - i;

	// if pkcs7 padding has been used, we expect the padding chars (sampled by
	// next_char) to have values specified by pad_value (depends on padding type)

	if(padding_size == pkcs7_pad_value){
//		cout << ">>>" << padding_size << " " << pkcs7_pad_value << endl;

		return Xstr::PKCS7_PADDING;
	}
	// else there is no padding
	else{
		return Xstr::NO_PADDING;
	}

}


/*
 * Returns a string that separates different blocks
 */

// TODO: when encoding conversions are complete, can just get exact
// chunks from the - Jesus christ, I hope you understand this etizolam-induced comment

string Xstr::pretty(EncodeType encoding /* = BASE64_ENCODED */){
	string pretty = string();
	string holder = string();

	// get string based on input encoding type
	switch(encoding){
		case ASCII_ENCODED:
			holder = this->as_ascii();

			break;
		case BASE64_ENCODED:
			holder = this->as_base64();

			break;
		case HEX_ENCODED:
			holder = this->as_hex();

			break;
		default:
			cout << "CR_str::pretty(): input encoding wasn't recognized" << endl;
			return string();
			break;
	}

	// 16 block size
	for(int blk = 0; blk < this->get_num_blocks(); blk++){
		for(int byte = 0; byte < 16; byte++){
			pretty += holder[(16*blk) + byte];
		}

		// after 3 blocks we want to go to a new line
		if((blk % 3) == 2)
			pretty += '\n';
		else // else just put a spacer
			pretty += ' ';

	}

	return pretty;
}



decoded_message solve_single_byte_xor(Xstr encoded){
	// TODO: replace this with init function
	decoded_message message;
	//decoded_message message = {
	//		.decoded = encoded,
	//		.key = string("\0"),
	//		.key_found = false,
	//		.score = 0
	//};

	Xstr possible_message = string();
	possible_message.resize(encoded.size(), 0);

	int max_score = 0;
	int max_key = 0;

	for(int key = 0; key < ASCII_MAX_VALUE; key++){
		string key_string = string();
		key_string.resize(encoded.size(), key);

		possible_message = Xstr( encoded ^ key_string );

		int score = possible_message.get_num_english_characters();

		if(score > max_score){
			max_score = score;
			max_key = key;
		}
	}

	// copy results into decoded_message struct
	string key_string = string();
	key_string.resize(encoded.size(), max_key);

	message.decoded = encoded ^ key_string;
	message.key = max_key;
	message.key_found = true;
	message.score = max_score;

	return message;
}

// struct that defines how to sort a vector containing keysize-distance pairs
struct myClass {
	bool operator() (std::pair<int, int> i, std::pair<int, int> j) { return (i.second < j.second); }
} hamming_distance_sort_struct;

decoded_message solve_repeating_key_xor(Xstr encoded){
	decoded_message message;

	vector< std::pair<int, int> > key_distances;

	// compute hamming distance between first and second groups of KEYSIZE LENGTH
	// save in vector as pair for sorting
	for(int keysize = MIN_KEYSIZE; keysize <= MAX_KEYSIZE; keysize++){
		int dist = 0;

		// sum together distances for all successive pairs
		for(int keypair = 0; keypair < (encoded.size() / keysize) - 1; keypair++){
			Xstr first_keysize =  encoded.substr((keypair * keysize)           , keysize);
			Xstr second_keysize = encoded.substr((keypair * keysize) + keysize , keysize);

			dist += first_keysize.hamming_distance( second_keysize );
		}

		std::pair<int, int> key_pair = std::pair<int, int>(keysize, dist);

		key_distances.push_back( key_pair );
	}

	// sort according to smallest distances
	std::sort (key_distances.begin(), key_distances.end(), hamming_distance_sort_struct);

	// variables for finding key that has the largest amount of english characters
	int max_score = 0;
	string max_key = string();

	// iterate through 5 keysizes smallest with the smallest hamming distance
	for(int keysize_idx = 0; keysize_idx < 5; keysize_idx++){
		int keysize = key_distances[keysize_idx].first;

		int tposed_block_size = encoded.size() / keysize;
	    string tposed_block = string();
	    tposed_block.resize(tposed_block_size, 0);

	    string multi_byte_key = string();
	    multi_byte_key.resize(keysize, 0);

	    for(int key_chr = 0; key_chr < keysize; key_chr++){

	    	// make transposed block of size keysize by picking out every n'th element (n = key_chr)
		    for(int i = 0; i < tposed_block_size; i++){
		    	tposed_block[i] = encoded[(i * keysize) + key_chr];
		    }

		    // find single-byte key that best solves according to histgram.
	    	decoded_message single_byte_key = solve_single_byte_xor(tposed_block);
	    	multi_byte_key[key_chr] = single_byte_key.key[0];
	    }

	    // decode message according to key and score it based on english characters
	    Xstr decoded_message = encoded ^ multi_byte_key;
	    int key_score = decoded_message.get_num_english_characters( );

	    // check if we've found maximum
	    if(key_score > max_score){
	    	max_score = key_score;
	    	max_key = multi_byte_key;
	    }
	}

	// return message decoded
	message.decoded = encoded ^ max_key;
	message.key = max_key;
	message.score = max_score;
	message.key_found = true;

	return message;
}
