#include<iostream>
#include<cstdlib>
#include<string>
#include<utility>
#include<algorithm>
#include<random>
#include<chrono>
#include "lib/ope.hh"
 
using namespace std;
 
#include "common.cpp"
 
//int main(){
int main(int argc, char* argv[]) {
        auto start = std::chrono::system_clock::now();
        cout << "argc = " << argc << endl;
        for(int i = 0; i < argc; i++)
                cout << "argv[" << i << "] = " << argv[i] << endl;
 
        if (argc < 5){
                cout << "usage encryptrange <key phrase> <plaintext range> <ciphertext range> <plaintext> [<precision>] [<shuffle>] [use vector map] [char range] [shuffle range]" << endl;
                return 1;
        }
        //first arg is keyphrase
        string keyPhrase = argv[1];
        //second arg is plaintext range
        string strP = argv[2];
        //third arg is ciphertext range
        string strC = argv[3];
        //fourth arg is plaintext
        string strPText = argv[4];
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
        unsigned int maxBytes = P/8;
 
        //OPE o("S0M3 $TR@NG Key", P, C);
        //initialise the OPE object
        OPE o(keyPhrase, P, C);
 
        //define ZZ variable and convert C-string plaintext input into ZZ.
        //catch conversion error and return empty string
        NTL::ZZ m1;
        NTL::ZZ l1(ZERO);
        NTL::ZZ u1(ZERO);
        //initialise the dynamic vector map
        if (bDynMap)
        {
            cout << "About to initialise dynamic vector map" << endl;   
            init_vector_map(keyPhrase, iCharRange, iShufRange);
            cout << "Dynamic vector map initialised" << endl;   
        }
        if (!use_vector_map)
        {
            std::seed_seq sseq(keyPhrase.begin(),keyPhrase.end());
            g.seed(sseq);
        }
        std::random_device rd;     // only used once to initialise (seed) engine
        std::mt19937 rng(rd());    // random-number engine used (Mersenne-Twister in this case)
        std::uniform_int_distribution<int> uni2(0,iShufRange); // guaranteed unbiased
        //processing a string plaintext
        string strpTextTemp;
        //strip non alphanumeric characters
        for( char c : strPText ) if( std::isalnum(c) ) strpTextTemp += c ;
        //copy back to strpText
        strPText = strpTextTemp;
        cout << "Input plaintext string is [[" << strPText << "]]" << endl;   
        string precText;
        precText = strPText;
        cout << "Justified plaintext is [[" << precText << "]]" << endl;   
        //convert to lower case
        std::transform(precText.begin(), precText.end(), precText.begin(), ::tolower);
        // OPE works with ZZ instead of usual integers
        //iterate through each character and multiply it by the relevant power of 256
        m1 = NTL::to_ZZ(ZERO);
        unsigned int pTextLength = precText.length();
        //find lower and upper bounds for first character
        int low_range = map_lower(precText[0]);
        int upper_range = map_upper(precText[0]);
        stringstream buffer;
        for (int i = low_range; i <= upper_range; i++)
        {
            NTL::ZZ l1(ZERO);
            NTL::ZZ u1(ZERO);
            NTL::ZZ m1(ZERO);
            for ( int a = 0; a < maxBytes; a+=1 ) 
            {
                NTL::ZZ n1(ZERO), n2(ZERO), n3(ZERO), n4(ZERO);
                if (a == 0)
                {
                  n1 = NTL::to_ZZ(i);
                  n3 = NTL::to_ZZ(i);
                  n4 = NTL::to_ZZ(i);
                }
                else if (a < pTextLength -1 && a < maxBytes)
                {
                  n1 = NTL::to_ZZ(map_lower(precText[a]));
                  n3 = NTL::to_ZZ(map_lower(precText[a]));
                  n4 = NTL::to_ZZ(map_lower(precText[a]));
                }
                else if (a == pTextLength -1 || a == maxBytes)
                {
                  n1 = NTL::to_ZZ(map_shuffle(precText[a]));
                  n3 = NTL::to_ZZ(map_lower(precText[a]));
                  n4 = NTL::to_ZZ(map_upper(precText[a]));
                }
                else
                {
                  //generate random number between 0 and shufRange
                  std::random_device rd;     // only used once to initialise (seed) engine
                  std::mt19937 rng(rd());    // random-number engine used (Mersenne-Twister in this case)
                  std::uniform_int_distribution<int> uni(0,iShufRange); // guaranteed unbiased
                  unsigned int random_integer = uni(rng);
                  n1 = NTL::to_ZZ(random_integer);
                  n3 = ZERO;
                  n4 = NTL::to_ZZ(iShufRange);
                }
                n2 = NTL::power(EXPONENT, maxBytes - a - 1);
                //cout << "In loop " << a+1 << " ; value of n1 is calculated as " << n1 << " and value of n2 is " << n2 << endl;
                m1 += n1*n2;
                //cout << "In loop " << a+1 << " ; value of m1 is calculated as " << m1 << endl;
                //lower value
                l1 += n3*n2;
                //upper value
                u1 += n4*n2;
            }
    
            //cout << "Converted plaintext is [[" << m1 << "]]" << endl;    
            cout << "Converted plaintext is [[" << m1 << "]]" << endl;    
            cout << "Lower range plaintext is [[" << l1 << "]]" << endl;    
            cout << "Upper range plaintext is [[" << u1 << "]]" << endl;    
            
            // call encrypt function
            NTL::ZZ c1 = o.encrypt(m1);
            NTL::ZZ c2(ZERO);
            NTL::ZZ c3(ZERO);
            if (l1 > ZERO)
            {
                c2 = o.encrypt(l1);
                cout << "lowerct = " << c2 << endl;
            }
            if (u1 > ZERO)
            {
                c3 = o.encrypt(u1);
                cout << "upperct = " << c3 << endl;
            }
            //convert ZZ into a string before returning to Java
            buffer << c2 << "|" << c3;
            if (i < upper_range)
            {
                buffer << "&";
            }
        }
 
        auto end = std::chrono::system_clock::now();
        auto elapsed =    std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        cout << "Time difference (microseconds) = " << elapsed << endl;
        string retString = buffer.str();
        cout << "Encryption ranges are [[" << retString << "]]" << endl;
        return 0;
}