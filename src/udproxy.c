/*
 ============================================================================
 Name        : udproxy.c
 Author      : MiniLight
 Version     :
 Copyright   : GPLv3
 Description : a simple proxy server for UDP
 ============================================================================
 */



#include "server.h"
#include "client.h"
#include "common.h"

int main(int argc, char **argv)
{
	int enable_isclient = 0;

	int i = 1;
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{
			print_help();
			exit(0);
		}
		//if enable "-c" startup as a client, else as a proxy server
		else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--clientmode") == 0)
		{
			enable_isclient = 1;
		}

	}

	if (enable_isclient == 1)
		return as_client(argc, argv);
	else
		return as_server(argc, argv);
}
