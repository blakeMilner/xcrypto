/*
 * crypto_test.cpp
 *
 *  Created on: Mar 20, 2016
 *      Author: blake
 */


#include "lib/codec.hpp"
#include "lib/block_cipher.hpp"
#include "lib/cookie.hpp"
#include "lib/rng.hpp"
#include "exercises.hpp"

#include <ctime>
#include <fstream>
#include <map>
#include <vector>
#include <array>
#include <string>

using namespace std;



/* Timing */
static std::clock_t start;

void tick(){
	// TODO: design for and test on windows
	// WORKS FOR LINUX ONLY
	start = std::clock();
}

void tock(){
	double epoch = (std::clock() - start) / (double)(CLOCKS_PER_SEC / 1000);

	// print as seconds if more than 1000 ms
	if(epoch > 1000){
		cout << "\t\t" << epoch / 1000.0 << " sec" << endl;
	}
	else{
		cout << "\t\t" << epoch << " ms" << endl;
	}
}



//  TODO: fault_check(key.size() != AES::BLOCKSIZE, message or error enum)

//  TODO:
// IDEA: make red and yellow alarms for debug messages.
// YELLOW = "padding up to ..." and RED = critical failure (index overrun)

//  TODO:
// IDEA: make command line arguments for specific exercise tests.
// e.g. ./crypto_test 3 8 12 18
// include ALL command for all test

// TODO: make files loaded in once, since some exercises reuse files

// TODO: remove static vars... ex. 27 has proven that they can be harmful with
// Xstr for some reason.

int main(int argc, char* argv[])
{
	list<int> test_set = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,21,22,23,24,25,26,27,28};

	for(auto ex: test_set){
		tick();

		switch(ex){
			case 1:			exercise1(); 	break;
			case 2:			exercise2(); 	break;
			case 3:			exercise3(); 	break;
			case 4:			exercise4(); 	break;
			case 5:			exercise5(); 	break;
			case 6:			exercise6(); 	break;
			case 7:			exercise7(); 	break;
			case 8:			exercise8(); 	break;
			case 9:			exercise9(); 	break;
			case 10:		exercise10(); 	break;
			case 11:		exercise11(); 	break;
			case 12:		exercise12(); 	break;
			case 13:		exercise13(); 	break;
			case 14:		exercise14(); 	break;
			case 15:		exercise15(); 	break;
			case 16:		exercise16(); 	break;
			case 17:		exercise17(); 	break;
			case 18:		exercise18(); 	break;
			case 19:		exercise19(); 	break;
			case 20:		exercise20(); 	break;
			case 21:		exercise21(); 	break;
			case 22:		exercise22(); 	break;
			case 23:		exercise23(); 	break;
			case 24:		exercise24(); 	break;
			case 25:		exercise25(); 	break;
			case 26:		exercise26(); 	break;
			case 27:		exercise27(); 	break;
			case 28:		exercise28(); 	break;
			default: cout << "Unknown exercise selected." << endl;
		}

		tock();

	}


	return 0;
}

