#include <jni.h>
#include <iostream>
#include <cstdlib>
#include <string>
#include <utility>
#include <algorithm>
#include <sstream>
#include <climits>
#include <exception>
#include <random>
#include "encryption_utils_callCPPFromJava.h"
#include "lib/ope.hh"

using namespace std;

#include "common_shuffle.cpp"

JNIEXPORT void JNICALL Java_encryption_utils_callCPPFromJava_initOPE (JNIEnv *env, jobject thisObj) {
    return;
}

OPE *onum;
string prev_num_passphrase="";
unsigned int prev_num_P=0;
unsigned int prev_num_C=0;
JNIEXPORT jstring JNICALL Java_encryption_utils_callCPPFromJava_encryptNum (JNIEnv *env, jobject thisObj, jstring pText, jint ptRange, jint ctRange, jstring jstrpassphrase) {
    
    //convert jints to unsigned ints
    unsigned int P = ptRange & INT_MAX;
    unsigned int C = ctRange & INT_MAX;

    //convert jstring to C-string (char *) for passphrase
    const char* inpassphrase = env->GetStringUTFChars(jstrpassphrase, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == inpassphrase) return env->NewStringUTF("");
    //assign to string
    string passphrase(inpassphrase);

    //free the initial jstring
    env->ReleaseStringUTFChars(jstrpassphrase, inpassphrase);

    //convert jstring to C-string (char *) for input plain text
    const char* inptext = env->GetStringUTFChars(pText, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == inptext) return env->NewStringUTF("");
    //assign to string
    string strpText(inptext);
    //check that string is numeric
    if (!is_number(strpText))
    {
        cout << "Input string is not positive numeric integer - exiting" << endl;
        //return empty string
        return env->NewStringUTF("");
    }
    //define ZZ variable and convert C-string plaintext input into ZZ. 
    //catch conversion error and return empty string
    NTL::ZZ m1;
    try
    {
        conv(m1, inptext);
    }
    catch (exception& e)
    {
        cout << "Caught exception casting input plaintext number to ZZ [[" << e.what() << "]]" << endl;
        //free the initial jstring
        try {
            env->ReleaseStringUTFChars(pText, inptext);
        }
        catch (exception& e1) {}
        //return empty string
        return env->NewStringUTF("");
    }

    //free the initial jstring
    env->ReleaseStringUTFChars(pText, inptext);

    //initialise the OPE library
    //OPE o(passphrase, P, C);
    if (prev_num_passphrase != passphrase || prev_num_P != P || prev_num_C != C)
    {
        onum = new OPE(passphrase, P, C);
        prev_num_passphrase = passphrase;
        prev_num_P = P;
        prev_num_C = C;
    }

    // call encrypt function
    NTL::ZZ c1 = onum->encrypt(m1);

    //convert ZZ into a string before returning to Java
    stringstream buffer;
    buffer << c1;
    string retString = buffer.str();
    return env->NewStringUTF(retString.c_str());
}

OPE *ostr;
string prev_str_passphrase="";
unsigned int prev_str_P=0;
unsigned int prev_str_C=0;
JNIEXPORT jstring JNICALL Java_encryption_utils_callCPPFromJava_encryptStr (JNIEnv *env, jobject thisObj, jstring pText, jint ptRange, jint ctRange, jstring jstrpassphrase, jint jprecision, jboolean jshuffle, jboolean jrandomMap, jint jcharRange, jint jshufRange) {

    cout << "Entered Java_callCPPFromJava_encryptStr" << endl;    
    //convert jints to unsigned ints
    unsigned int P = ptRange & INT_MAX;
    unsigned int C = ctRange & INT_MAX;
    unsigned int precision = jprecision & INT_MAX;
	//set bool for shuffle
	bool bShuffle = (bool) jshuffle;
    //set bool for randomMap
    bool bRandomMap = (bool) jrandomMap;
    unsigned int charRange = jcharRange & INT_MAX;
    unsigned int shufRange = jshufRange & INT_MAX;
    NTL::ZZ EXPONENT = NTL::to_ZZ(shufRange+1);
	
    // unsigned int maxBytes = P/8;
    // maximum number of plaintext characters that can be encrypted is
    // related to the input allowed shuffle range and the plaintext numeric range
    // value is p/(log2(number of values in shuf range))
    unsigned int maxBytes = P/log2(shufRange + 1);
    cout << "max characters is " << maxBytes << endl;

    //convert jstring to C-string (char *)
    const char* inpassphrase = env->GetStringUTFChars(jstrpassphrase, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == inpassphrase) return env->NewStringUTF("");
    //assign to string
    string passphrase(inpassphrase);
    cout << "Input passphrase is [[" << passphrase << "]]" << endl;    
    cout << "Input plaintext range is [[" << P << "]]" << endl;    
    cout << "Input ciphertext range is [[" << C << "]]" << endl;    

    //free the initial jstring
    env->ReleaseStringUTFChars(jstrpassphrase, inpassphrase);

    //initialise the OPE library
    //OPE o(passphrase, P, C);
    if (prev_str_passphrase != passphrase || prev_str_P != P || prev_str_C != C)
    {
        ostr = new OPE(passphrase, P, C);
        prev_str_passphrase = passphrase;
        prev_str_P = P;
        prev_str_C = C;
    }

    //create left padded string of length "precision" from the input pText
    //convert jstring to C-string (char *)
    const char* inptext = env->GetStringUTFChars(pText, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == inptext) return env->NewStringUTF("");
    //assign to string
    string strpText(inptext);

    //free the initial jstring
    env->ReleaseStringUTFChars(pText, inptext);

    cout << "Input plaintext is [[" << strpText << "]]" << endl;
	string strpTextTemp;
	//strip non alphanumeric characters
    for( char c : strpText ) if( std::isalnum(c) ) strpTextTemp += c ;
	//copy back to strpText
	strpText = strpTextTemp;
    string precText;
    //if (strpText.length() >= precision)
    //{
    //   precText = strpText.substr(0,precision);
    //}
    //else
    //{
    //    precText = strpText;
	//	while (precText.length() < precision) precText.append("0");
        //line below compiles on Centos but not Ubuntu
		//precText.append<int>(precision-strpText.length(),'0');
    //} 
    precText = strpText;
    cout << "Justified plaintext is [[" << precText << "]]" << endl;    
    //precText is now a string which is left justified and padded with 0x00 to the right
    std::transform(precText.begin(), precText.end(), precText.begin(), ::tolower);
    // OPE works with ZZ instead of usual integers
    //iterate through each character and multiply it by the relevant power of EXPONENT
    NTL::ZZ m1(ZERO);
    unsigned int pTextLength = precText.length();
    if (bShuffle) {
        cout << "About to initialise dynamic vector map" << endl;   
        init_vector_map(passphrase, charRange, shufRange);
        cout << "Dynamic vector map initialised" << endl;
    }
    if (!use_vector_map)
    {
        std::seed_seq sseq(passphrase.begin(),passphrase.end());
        g.seed(sseq);
    }
    std::random_device rd;     // only used once to initialise (seed) engine
    std::mt19937 rng(rd());    // random-number engine used (Mersenne-Twister in this case)
    std::uniform_int_distribution<int> uni2(0,shufRange); // guaranteed unbiased
 
    for ( int a = 0; a < maxBytes; a+=1 ) {
		NTL::ZZ n1(ZERO), n2(ZERO);
		if (!bShuffle) {
            if (a < pTextLength)
            {
			  n1 = NTL::to_ZZ(unsigned(precText[a]));
            }
            else
            {
              n1 = ZERO;
            }
		}
		else
		{
		    if (a == 0)
		    {
		      int firstShuf = map_shuffle(precText[a]);
		      //cout << "First char is mapped to " << firstShuf << endl;
              n1 = NTL::to_ZZ(firstShuf);
            }
            else if (a < pTextLength -1 && a < maxBytes)
            {
			  n1 = NTL::to_ZZ(map_lower(precText[a]));
            }
            else if (a == pTextLength -1 || a == maxBytes)
            {
			  n1 = NTL::to_ZZ(map_lower(precText[a]));
            }
            else
            {
              n1 = NTL::to_ZZ(uni2(rng));
            }
		}
		n2 = NTL::power(EXPONENT, maxBytes - a - 1);
		//cout << "In loop " << a+1 << " ; value of n1 is calculated as " << n1 << " and value of n2 is " << n2 << endl;
		m1 += n1*n2;
		//cout << "In loop " << a+1 << " ; value of m1 is calculated as " << m1 << endl;
    }

    cout << "Converted plaintext is [[" << m1 << "]]" << endl;    
    
    // call encrypt function
    NTL::ZZ c1 = ostr->encrypt(m1);
    cout << "Ciphertext is [[" << c1 << "]]" << endl;    

    //convert ZZ into a string before returning to Java
    stringstream buffer;
    buffer << c1;
    string retString = buffer.str();
    return env->NewStringUTF(retString.c_str());
}

JNIEXPORT jstring JNICALL Java_encryption_utils_callCPPFromJava_decrypt (JNIEnv *env, jobject thisObj, jstring cText, jint ptRange, jint ctRange, jstring jstrpassphrase) {
	//this function decrypts a numeric plaintext
    //convert jints to unsigned ints
    unsigned int P = ptRange & INT_MAX;
    unsigned int C = ctRange & INT_MAX;

    //convert jstring to C-string (char *)
    const char* inpassphrase = env->GetStringUTFChars(jstrpassphrase, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == inpassphrase) return env->NewStringUTF("");
    //assign to string
    string passphrase(inpassphrase);

    //free the initial jstring
    env->ReleaseStringUTFChars(jstrpassphrase, inpassphrase);

    //convert jstring to C-string (char *)
    const char* incText = env->GetStringUTFChars(cText, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == incText) return env->NewStringUTF("");
    //assign to string
    string strCText(incText);

    //free the initial jstring
    env->ReleaseStringUTFChars(cText, incText);
    //check that input cypher text was numeric string
    if (!is_number(strCText))
    {
        cout << "Input cyphertext string is not positive numeric integer - exiting" << endl;
        //return empty string
        return env->NewStringUTF("");
    }

    //initialise the OPE library
    OPE o(passphrase, P, C);

    // OPE works with ZZ instead of usual integers
    NTL::ZZ c1(NTL::INIT_VAL,strCText.c_str());

    // call decrypt function
    NTL::ZZ m1 = o.decrypt(c1);

    //convert ZZ into a string before returning to Java
    stringstream buffer;
    buffer << m1;
    string retString = buffer.str();
    return env->NewStringUTF(retString.c_str());
}

JNIEXPORT jstring JNICALL Java_encryption_utils_callCPPFromJava_decryptStr (JNIEnv *env, jobject thisObj, jstring cText, jint ptRange, jint ctRange, jstring jstrpassphrase, jint jprecision, jboolean jshuffle, jboolean jrandomMap, jint jcharRange, jint jshufRange) {
    
    //convert jints to unsigned ints
    unsigned int P = ptRange & INT_MAX;
    unsigned int C = ctRange & INT_MAX;
	//set bool for shuffle - TODO - pass via input variables
	bool bShuffle = (bool)jshuffle;
    //set bool for randomMap
    bool bRandomMap = (bool) jrandomMap;
    unsigned int charRange = jcharRange & INT_MAX;
    unsigned int shufRange = jshufRange & INT_MAX;
    NTL::ZZ EXPONENT = NTL::to_ZZ(shufRange+1);

    //convert jstring to C-string (char *)
    const char* inpassphrase = env->GetStringUTFChars(jstrpassphrase, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == inpassphrase) return env->NewStringUTF("");
    //assign to string
    string passphrase(inpassphrase);

    //free the initial jstring
    env->ReleaseStringUTFChars(jstrpassphrase, inpassphrase);

    //convert jstring to C-string (char *)
    const char* incText = env->GetStringUTFChars(cText, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == incText) return env->NewStringUTF("");
    //assign to string
    string strCText(incText);

    //free the initial jstring
    env->ReleaseStringUTFChars(cText, incText);
    //check that input cypher text was numeric string
    if (!is_number(strCText))
    {
        cout << "Input cyphertext string is not positive numeric integer - exiting" << endl;
        //return empty string
        return env->NewStringUTF("");
    }

    //initialise the OPE library
    OPE o(passphrase, P, C);

    // OPE works with ZZ instead of usual integers
    NTL::ZZ c1(NTL::INIT_VAL,strCText.c_str());

    // call decrypt function
    NTL::ZZ m1 = o.decrypt(c1);
    //cout << "Decrypted number is " << m1 << endl;
    //convert ZZ into a string before returning to Java
    //determine number of characters
    unsigned int num_chars = 0;
    NTL::ZZ zzTemp;
    while (m1 > zzTemp)
    {
        num_chars++;
        zzTemp = NTL::power(EXPONENT,num_chars);
    }
    //cout << "Number of characters calculated as " << num_chars << endl;
    //assign character array to hold decrypted characters + null terminator
    char pChars[num_chars + 1];
    uint temp_int = 0;
    if (bShuffle) {
        cout << "About to initialise dynamic vector map" << endl;   
        init_vector_map(passphrase, charRange, shufRange);
        cout << "Dynamic vector map initialised" << endl;
    }
    //assign each character by converting from unsigned int
    for (int a = 0; a < num_chars; a++)
    {
        //calculate "a"th character by treating m1 as base-EXPONENT number
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
        //remove the leading "character" from m1 by subtracting leading base-EXPONENT digit
        m1 = m1 - zzChar*NTL::power(EXPONENT, num_chars - 1 - a);
        //cout << "m1 is now " << m1 << endl;
    }
    //null terminate the string
    pChars[num_chars] = '\0';
    return env->NewStringUTF(pChars);
}

JNIEXPORT jstring JNICALL Java_encryption_utils_callCPPFromJava_encryptionRange (JNIEnv *env, jobject thisObj, jstring pText, jint ptRange, jint ctRange, jstring jstrpassphrase, jint jprecision, jboolean jshuffle, jboolean jrandomMap, jint jcharRange, jint jshufRange) {

    cout << "Entered Java_encryption_utils_callCPPFromJava_encryptionRange" << endl;    
    //convert jints to unsigned ints
    unsigned int P = ptRange & INT_MAX;
    unsigned int C = ctRange & INT_MAX;
    unsigned int precision = jprecision & INT_MAX;
	//set bool for shuffle
	bool bShuffle = (bool) jshuffle;
    //set bool for randomMap
    bool bRandomMap = (bool) jrandomMap;
    unsigned int charRange = jcharRange & INT_MAX;
    unsigned int shufRange = jshufRange & INT_MAX;
    NTL::ZZ EXPONENT = NTL::to_ZZ(shufRange+1);
    unsigned int maxBytes = P/8;
	
    //convert jstring to C-string (char *)
    const char* inpassphrase = env->GetStringUTFChars(jstrpassphrase, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == inpassphrase) return env->NewStringUTF("");
    //assign to string
    string passphrase(inpassphrase);
    cout << "Input passphrase is [[" << passphrase << "]]" << endl;    
    cout << "Input plaintext range is [[" << P << "]]" << endl;    
    cout << "Input ciphertext range is [[" << C << "]]" << endl;    

    //free the initial jstring
    env->ReleaseStringUTFChars(jstrpassphrase, inpassphrase);

    //initialise the OPE library
    //OPE o(passphrase, P, C);
    if (prev_str_passphrase != passphrase || prev_str_P != P || prev_str_C != C)
    {
        ostr = new OPE(passphrase, P, C);
        prev_str_passphrase = passphrase;
        prev_str_P = P;
        prev_str_C = C;
    }

    //create left padded string of length "precision" from the input pText
    //convert jstring to C-string (char *)
    const char* inptext = env->GetStringUTFChars(pText, NULL);
    //check NULL first - return empty string if NULL
    if (NULL == inptext) return env->NewStringUTF("");
    //assign to string
    string strpText(inptext);

    //free the initial jstring
    env->ReleaseStringUTFChars(pText, inptext);

	string strpTextTemp;
	//strip non alphanumeric characters
    for( char c : strpText ) if( std::isalnum(c) ) strpTextTemp += c ;
	//copy back to strpText
	strpText = strpTextTemp;

    cout << "Input plaintext is [[" << strpText << "]]" << endl;    
    string precText;
    precText = strpText;

    cout << "Justified plaintext is [[" << precText << "]]" << endl;    
    // OPE works with ZZ instead of usual integers
    std::transform(precText.begin(), precText.end(), precText.begin(), ::tolower);
    //iterate through each character and multiply it by the relevant power of EXPONENT
	//define ZZ variable and convert C-string plaintext input into ZZ. 
	//catch conversion error and return empty string
    unsigned int pTextLength = precText.length();
    stringstream buffer;
    cout << "About to initialise dynamic vector map" << endl;   
    init_vector_map(passphrase, charRange, shufRange);
    cout << "Dynamic vector map initialised" << endl;
    //find range of values for first character
    vector<int> value_range = get_range(precText[0]);
    int no_values = value_range.size();
    for (int i = 0; i < no_values; i++)
    {
    	NTL::ZZ l1(ZERO);
    	NTL::ZZ u1(ZERO);
        NTL::ZZ m1(ZERO);
        for ( int a = 0; a < maxBytes; a+=1 ) 
        {
    		NTL::ZZ n1(ZERO), n2(ZERO), n3(ZERO), n4(ZERO);
    		if (a == 0)
    		{
              //cout << "First char is mapped to " << value_range[i] << endl;
              //n1 = NTL::to_ZZ(value_range[i]);
              n3 = NTL::to_ZZ(value_range[i]);
              n4 = NTL::to_ZZ(value_range[i]);
    		}
            else if (a < pTextLength -1 && a < maxBytes)
            {
              //n1 = NTL::to_ZZ(map_lower(precText[a]));
              n3 = NTL::to_ZZ(map_lower(precText[a]));
              n4 = NTL::to_ZZ(map_lower(precText[a]));
            }
            else if (a == pTextLength -1 || a == maxBytes)
            {
              //n1 = NTL::to_ZZ(map_lower(precText[a]));
              n3 = NTL::to_ZZ(map_lower(precText[a]));
              n4 = NTL::to_ZZ(map_lower(precText[a]));
            }
            else
            {
              //generate random number between 0 and shufRange
              //std::random_device rd;     // only used once to initialise (seed) engine
              //std::mt19937 rng(rd());    // random-number engine used (Mersenne-Twister in this case)
              //std::uniform_int_distribution<int> uni(0,shufRange); // guaranteed unbiased
              //unsigned int random_integer = uni(rng);
              //n1 = NTL::to_ZZ(random_integer);
              n3 = ZERO;
              n4 = NTL::to_ZZ(shufRange);
            }
            n2 = NTL::power(EXPONENT, maxBytes - a - 1);
    		//cout << "In loop " << a+1 << " ; value of n1 is calculated as " << n1 << " and value of n2 is " << n2 << endl;
    		//m1 += n1*n2;
    		//cout << "In loop " << a+1 << " ; value of m1 is calculated as " << m1 << endl;
    		//lower value
    		l1 += n3*n2;
    		//upper value
    		u1 += n4*n2;
        }
    
        //cout << "Converted plaintext is [[" << m1 << "]]" << endl;    
    	cout << "Lower range plaintext is [[" << l1 << "]]" << endl;    
    	cout << "Upper range plaintext is [[" << u1 << "]]" << endl;    
        
        // call encrypt function
        // NTL::ZZ c1 = o.encrypt(m1);
    	NTL::ZZ c2(ZERO);
    	NTL::ZZ c3(ZERO);
    	if (l1 > ZERO)
    	{
    		c2 = ostr->encrypt(l1);
    		cout << "lowerct = " << c2 << endl;
    	}
    	if (u1 > ZERO)
    	{
    		c3 = ostr->encrypt(u1);
    		cout << "upperct = " << c3 << endl;
    	}
        //convert ZZ into a string before returning to Java
        buffer << c2 << "|" << c3;
        if (i < no_values - 1)
        {
            buffer << "&";
        }
    }
    string retString = buffer.str();
    cout << "Encryption ranges are [[" << retString << "]]" << endl;
    return env->NewStringUTF(retString.c_str());
}
