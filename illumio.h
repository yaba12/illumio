#include <string>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;
class Firewall
{
public:
  Firewall(string file);
  bool accept_packet(string dir, string protocol, int port, string ip);
private:
unordered_map<string, int> map;
};
