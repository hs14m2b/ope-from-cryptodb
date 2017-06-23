#include<iostream>
#include<cstdlib>
#include<string>
#include<sstream>
#include<utility>
#include<algorithm>
 
#include "lib/ope.hh"
 
using namespace std;
 
#include "common_shuffle.cpp"
 
//int main(){
int main(int argc, char* argv[]) {
        cout << "argc = " << argc << endl;
        for(int i = 0; i < argc; i++)
                cout << "argv[" << i << "] = " << argv[i] << endl;
 
        if (argc < 5){
                cout << "usage example <key phrase> <plaintext range> <ciphertext range> <ciphertext> [<precision>] [<shuffle>] [use vector map] [char range]" << endl;
                return 1;
        }
        //first arg is keyphrase
        string keyPhrase = argv[1];
        //second arg is plaintext range
        string strP = argv[2];
        //third arg is ciphertext range
        string strC = argv[3];
        //fourth arg is cyphertext
        string strCText = argv[4];
        string strPrecision = "0";
        string strShuffle = "0";
        string strDynMap = "0";
        string strCharRange = "36";
        string strShufRange = "255";
        if (argc > 5) {
                        // precision has been specified - we are encrypting a string
                        strPrecision = argv[5];
        }
        if (argc > 6) {
                        // shuffle has been specified - we are encrypting a string potentially with the character binary values to be shuffled
                        strShuffle = argv[6];
        }
       if (argc > 7) {
                        // dynamic map has been specified - we are encrypting a string with the mapping to be dynamically determined
        strDynMap = argv[7];
        }
        if (argc > 8) {
            // character range has been specified - we are encrypting a string with a specific character range
            strCharRange = argv[8];
        }
        if (argc > 9) {
            // shuffle range has been specified - we are encrypting a string with a specific character range
            strShufRange = argv[9];
        }
       // plaintext range's length in bits (plaintexts are in [0, 2**P-1]
        //unsigned int P = 64;
        unsigned int P = atoi(strP.c_str());
        // ciphertext range's length in bits (ciphertexts are in [0, 2**C-1]
        //unsigned int C = 128;
        unsigned int C = atoi(strC.c_str());
        // convert the precision to an integer
        unsigned int iPrecision = atoi(strPrecision.c_str());
        // convert the shuffle to a bool
        bool bShuffle = atoi(strShuffle.c_str());
        // convert the vecmap to a bool
        bool bDynMap = atoi(strDynMap.c_str());
        // convert the char range to an integer
        unsigned int iCharRange = atoi(strCharRange.c_str());
         // convert the shuf range to an integer
        unsigned int iShufRange = atoi(strShufRange.c_str());
        NTL::ZZ EXPONENT = NTL::to_ZZ(iShufRange+1);
 
        //OPE o("S0M3 $TR@NG Key", P, C);
                                //initialise the OPE object
        OPE o(keyPhrase, P, C);
 
                                //define ZZ variable and convert C-string plaintext input into ZZ.
                                //catch conversion error and return empty string
                                cout << "Input cypertext number is [[" << strCText << "]]" << endl;   
                                if (!is_number(strCText))
                                {
                                                cout << "Input cyphertext string is not positive numeric integer - exiting" << endl;
                                                //return 1
                                                return 1;
                                }
                               
                                // OPE works with ZZ instead of usual integers
                                NTL::ZZ c1(NTL::INIT_VAL,strCText.c_str());
                                // call decrypt function
                                NTL::ZZ m1 = o.decrypt(c1);
                                cout << "Decrypted number is " << m1 << endl;
                                //convert ZZ into a string before returning to Java
                                stringstream buffer;
                                buffer << m1;
                                string strPText = buffer.str();
 
                                if (iPrecision > 0){
                                                //processing a string plaintext
                                                //initialise the dynamic vector map
                                                if (bDynMap)
                                                {
                                                    cout << "About to initialise dynamic vector map" << endl;   
                                                                init_vector_map(keyPhrase, iCharRange, iShufRange);
                                                    cout << "Dynamic vector map initialised" << endl;   
                                                }
                                                //convert ZZ into a string before returning
                                                //determine number of characters
                                                unsigned int num_chars = 0;
                                                NTL::ZZ zzTemp;
                                                while (m1 > zzTemp)
                                                {
                                                                num_chars++;
                                                                zzTemp = NTL::power(EXPONENT,num_chars);
                                                }
                                                cout << "Number of characters calculated as " << num_chars << endl;
                                                //assign character array to hold decrypted characters + null terminator
                                                char pChars[num_chars + 1];
                                                uint temp_int = 0;
                                                //assign each character by converting from unsigned int
                                                for (int a = 0; a < num_chars; a++)
                                                {
                                                                //calculate "a"th character by treating m1 as base-256 number
                                                                NTL::ZZ zzChar = m1/(NTL::power(EXPONENT, num_chars - 1 - a));
                                                                //cout << "Character at index " << a << " is " << zzChar << endl;
                                                                //convert result into unsigned int
                                                                conv(temp_int, zzChar);
                                                                //assign uint to "a"th position in array (a char and uint are same)
                                                                if (!bShuffle){
                                                                                pChars[a]=unsigned(temp_int);
                                                                }
                                                                else
                                                                {
                                                                                pChars[a]=unmap_shuffle(temp_int);
                                                                }
                                                                //remove the leading "character" from m1 by subtracting leading base-256 digit
                                                                m1 = m1 - zzChar*NTL::power(EXPONENT, num_chars - 1 - a);
                                                                //cout << "m1 is now " << m1 << endl;
                                                }
                                                //null terminate the string
                                                pChars[num_chars] = '\0';
                                                strPText = string(pChars);
                                }
        cout << "dec(c1) = " << strPText << endl;
 
                                cout << "plaintext = " << strPText << endl;
 
        return 0;
}