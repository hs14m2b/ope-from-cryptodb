static NTL::ZZ ZERO = NTL::to_ZZ(0);
std::vector< vector<int> > vector_map;
std::mt19937 g;
bool use_vector_map = false;
string current_keyPhrase = "";
int current_char_range = 0;
int current_shuf_range = 0;
void init_vector_map(string keyPhrase, int char_range, int shuf_range)
{
    if (use_vector_map)
    {
        std::cout << "Vector Map is already initialised" << endl; 
        //force clear vector_map
        //for (int j = 0; j < vector_map.size(); j++)
        //{
        //    vector_map[j].clear();
        //} 
        //vector_map.clear();
        //std::cout << "Vector Map cleared" << endl;
        if (current_keyPhrase.compare(keyPhrase) != 0 || current_char_range != char_range || current_shuf_range != shuf_range)
        {
            std::cout << "Keyphrase or character ranges have changed, so clearing vector map" << endl; 
            for (int j = 0; j < vector_map.size(); j++)
            {
                vector_map[j].clear();
            } 
            vector_map.clear();
            std::cout << "Vector Map cleared" << endl;
        }
        else
        {
            std::cout << "Keyphrase and character ranges are the same, so maintaining vector map" << endl;
            return;
        } 
    }
    current_keyPhrase = keyPhrase;
    current_char_range = char_range;
    current_shuf_range = shuf_range;
    //create a uniform distribution across the plaintext character range
    std::uniform_int_distribution<int> uni(0,char_range-1); // guaranteed unbiased
    //use keyPhrase to create seed sequence
    std::seed_seq sseq(keyPhrase.begin(),keyPhrase.end());
    g.seed(sseq);
    std::cout << "Initialised uniform distribution and random seed" << endl; 
    if (vector_map.size() > 0)
    {
        //clear the vector_map
        vector_map.clear();
        std::cout << "Vector Map cleared" << endl; 
    }
    while (vector_map.size() == 0)
    {
        //resize the vector_map to hold char_range entries
        vector_map.resize(char_range);
        std::cout << "Vector Map resized to size " << char_range << endl; 
        //assign the shuf_range values randomly to the char_range
        for (int b = 0; b <= shuf_range; b++)
        {
            int x = uni(g);
            vector_map[x].push_back(b);
        }
        //check that each entry in the vector_map has at least one value
        for (int c = 0; c < char_range; c++)
        {
            if (vector_map[c].size() == 0)
            {
                //the plaintext char does not have a value in the shuffled range
                //clear the vector_map and re-assign values
                vector_map.clear();
            }
        }
    }
    use_vector_map = true;
}
 
unsigned int arr_position(char input_char)
{
    //cout << "In arr_position for char " << input_char <<endl;
    int offset = 48;
    // cast char to int
    unsigned int iValue = unsigned(input_char);
    //cout << "iValue is " << iValue <<endl;
    if (iValue > 57)
    {
                    offset = 87;
    }
    iValue = iValue - offset;
    //iValue now in range 0-35
    return iValue;
}
 
unsigned int map_lower(char input_char)
{
    //cout << "In map_lower for char " << input_char <<endl;
    return vector_map[arr_position(input_char)][0];
}
unsigned int map_upper(char input_char)
{
    unsigned int iValue = arr_position(input_char);
    unsigned int max_position = vector_map[iValue].size() -1;
    return vector_map[iValue][max_position];
}

unsigned int map_shuffle(char input_char)
{
    unsigned int iValue = arr_position(input_char);
    unsigned int no_values = vector_map[iValue].size();
    //cout << "In map shuffle with " << low_value << " low val and " << high_value << " hig val" << endl;
    if (no_values == 1)
    {
      return vector_map[iValue][0];
    }
    else
    {  
        //generate random number to select an element
        std::random_device rd;     // only used once to initialise (seed) engine
        std::mt19937 rng(rd());    // random-number engine used (Mersenne-Twister in this case)
        std::uniform_int_distribution<int> uni(0,no_values - 1); // guaranteed unbiased
        unsigned int random_integer = uni(rng);
        //cout << "low_value is " << low_value << " high value is " << high_value << " random offset is " << random_integer << endl;
        return vector_map[iValue][random_integer];
    }
}

unsigned int unmap_shuffle(unsigned int input_int)
{
    unsigned int i = 0;
    //loop through vector map to find which has input_int as a mapped value
    bool found = false;
    while (!found)
    {
        for (int j = 0; j < vector_map[i].size(); j++)
        {
            if (vector_map[i][j] == input_int)
            {
                found = true;
            }
        }
        if (!found)
        {
            i++;
        }
    }
    if (i > 9)
    {
        i += 87;
    }
    else
    {
        i += 48;
    }
    return i;
}

vector<int> get_range(char input_char)
{
    unsigned int iValue = arr_position(input_char);
    return vector_map[iValue];
}

bool is_number(const std::string& s)
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it == s.end();
}
 