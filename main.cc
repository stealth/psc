#include <iostream>
#include "misc.h"
#include "rc4.h"

using namespace std;

int main()
{
	unsigned char buf1[128], buf2[128];
	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));
	b64_encode("Hello\n", 6, buf1);
	cout<<buf1<<endl;
	b64_decode((char*)buf1, buf2);
	cout<<buf2<<endl;
	return 0;
}


