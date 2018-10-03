#include <iostream>
#include <string>
using namespace std;


void hexToText(string hex)
{
    size_t len = hex.length();
    std::string newString;
    for(int i=0; i< len; i+=2)
    {
        string byte = hex.substr(static_cast<unsigned long>(i), 2);
        auto chr = (char) (int)strtol(byte.c_str(), nullptr, 16);
        newString.push_back(chr);
    }

    cout << newString << endl;
}



void strToHex(string text)
{
    for(int i = 0 ; i < text.length() ; i++)
    {
        cout << "[" << dec << i << "]: " << hex << (text.at(i) - '0') << "\n";
    }

}
int main()
{


    string text;
    cin >> text;

    hexToText("48656c6c6f");


}