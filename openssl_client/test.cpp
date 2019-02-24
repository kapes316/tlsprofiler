#include <iostream>
#include "OpenSSLClient.h"

using namespace std;

const char *VERSION="openssl-1.1.1";

int main(int argc, char** argv)
{
  if(argc < 3)
  {
    cout << "Usage: ./oc id host [filename]" << endl;
    return(1);
  }
  string versionID(VERSION);

  versionID += "-";
  versionID += argv[1];

  OpenSSLClient oc(argv[2], (argc > 3)?argv[3]:"");

  oc.setVersionID(versionID.c_str());
  oc.secureConnect();
  oc.writeJSON();
  oc.disconnect();

  return 0;
}
