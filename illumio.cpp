#include "illumio.h"
using namespace std;
Firewall::Firewall(string file) {
  ifstream tempfile(file);
  string line;
  while(getline(tempfile,line)) {

    // check if there are no inclusives
    if(line.find('-') != string::npos) {
      map[line] = 1;
    } else {

      //split by commas
      std::vector<string> temp;
      string delim = ",";
      size_t pos = 0;
      while((pos= line.find(delim)) != string::npos) {
        temp.push_back(line.substr(0,pos));
        line.erase(0,pos + delim.length());
      }
      temp.push_back(line);

      //check if ports have inclusive and split it
      string newdelim = "-";
      size_t newpos = 0;
      std::vector<string> port;
      string first = temp[2];
      if((newpos = first.find(newdelim)) != string::npos) {
        port.push_back(first.substr(0,newpos));
        first.erase(0, newpos + newdelim.length());
      }
      port.push_back(first);

      //check if ips have inclusives
      //place order of inclusive octets of port vector
      std::vector<string> ipvec;
      string perioddelim = ".";
      size_t ppos = 0;
      string ip = temp[3];
      while((ppos= ip.find(perioddelim)) != string::npos) {
        ipvec.push_back(ip.substr(0,ppos));
        ip.erase(0,ppos + perioddelim.length());
      }
      ipvec.push_back(ip);
      std::vector<string> range;
      for(size_t i = 0; i < ipvec.size(); i++) {
        if(ipvec[i].find(newdelim) != string::npos) {
          range.push_back(to_string(i));
        }
      }

      //split all ip inclusives
      //vector of vector of range
      std::vector<vector<string> > ranges;
      for(size_t j = 0; j < range.size(); j++) {
        std::vector<string> currange;
        string iprange = ipvec[stoi(range[j])];
        size_t temppos = 0;
        if((temppos = iprange.find(newdelim)) != string::npos) {
          currange.push_back(iprange.substr(0,temppos));
          first.erase(0, temppos + newdelim.length());
        }
        currange.push_back(iprange);
        ranges.push_back(currange);
      }

      //only have port inclusives, combine
      if(range.size() == 0 && port.size() > 1) {
        int begin = stoi(port[0]);
        int end = stoi(port[1]);
        for(int i = begin; i < end; i++) {
          string newstring = temp[0] + "," + temp[1] + "," + to_string(i) + "," + temp[3];
          map[newstring] = 1;
        }

        //only have ip inclusvies, combine.
      } else if(port.size() == 1 && range.size() != 0) {
        for(size_t i = 0; i < range.size(); i++ ){
          int begin = stoi(ranges[i][0]);
          int end = stoi(ranges[i][1]);
          for(size_t j = begin; j < end; j++) {
            ipvec[stoi(range[i])] = to_string(j);
            string newstring = temp[0] + "," + temp[1] + "," + temp[2] + "," + ipvec[0] + "." + ipvec[1] + "." + ipvec[2] + "." + ipvec[3] + "." + ipvec[4];
            map[newstring] = 1;
          }
        }
      }

      //have both ip and port inclusives, combine.
      else {
        for(size_t i = 0; i < range.size(); i++ ){
          int begin = stoi(ranges[i][0]);
          int end = stoi(ranges[i][1]);
          for(size_t j = begin; j < end; j++) {
            ipvec[stoi(range[i])] = to_string(j);
            int begin = stoi(port[0]);
            int end = stoi(port[1]);
            for(int i = begin; i < end; i++) {
              string newstring = temp[0] + "," + temp[1] + "," + to_string(i) + "," + ipvec[0] + "." + ipvec[1] + "." + ipvec[2] + "." + ipvec[3] + "." + ipvec[4];
              map[newstring] = 1;
            }
          }
      }
    }
  }
}
}

bool Firewall::accept_packet(string dir, string protocol, int port, string ip) {
  string fire = dir + "," + protocol + "," + std::to_string(port) + "," + ip;
  if (map.find(fire) ==  map.end()) {
    return false;
  }
  return true;
}
