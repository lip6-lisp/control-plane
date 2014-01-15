#include <stdio.h>
int main(void *argc, void *argv)
{
	FILE *f;
	char *fname[2];
	fname[0] = "opencp_xtr.xml";
	f = fopen(fname[0],"r");
	fclose(f);
        return 1;
}

