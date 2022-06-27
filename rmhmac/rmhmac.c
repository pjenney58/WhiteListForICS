#ifdef __LINUX__
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic push
#endif

#include "aerolock.h"
#include <getopt.h>

int32_t __add_to_profile(uint8_t* __hmac)
{
	int32_t __retval = ERROR;
	int32_t __fd     = 0;

	__fd = open("/var/lib/rmi/hmacs.profile", O_APPEND | O_RDWR);
	if(__fd > 0)
	{
		if(write(__fd, __hmac, 32) != -1)
		{
			__retval = NOERROR;
		}
		else
		{
			fprintf(stderr, "__add_to_profile(%d) failed with %s\n", __fd, strerror(errno));
		}

		close(__fd);
	}

	return __retval;
}

int8_t* __strip_path(int8_t* __pathname)
{
	int8_t* __cp = NULL;

	/*
	 * Handle ./foo/bar/this
	 */
	if(__pathname[0] == '.' && __pathname[1] == '/')
	{
		__pathname++;
	}

	if(strchr(__pathname, '/'))
	{
		__cp = __pathname;
		__cp += strlen(__pathname);

		while(*--__cp !='/')
			;

		return __cp + 1;
	}

	return __pathname;
}

int32_t delete_hmac(int8_t* pathname)
{
    return(__bdb_delete_hmac(__strip_path(pathname)));
}

int32_t insert_hmac(int8_t* __pathname)
{
	uint8_t* __hmac   = NULL;
    int32_t  __retval = NOERROR;

    if((__hmac = (uint8_t*)malloc(HMAC256_LEN)) == NULL)
    {
    	__retval = ERROR;
    	goto out;
    }

    if(__get_signature(__pathname, __hmac))
    {
        if(__bdb_write_hmac(__strip_path(__pathname), __hmac))
        {
        	__retval = __add_to_profile(__hmac);
        }
        else
        {
        	fprintf(stderr, "insert_hmac() - bdb_write() failed\n");
        }
    }
	else
	{
		fprintf(stderr, "Failed to generate signature for %s\n", __pathname);
	}

out:
    if(__hmac)
    {
    	free(__hmac);
    	__hmac = NULL;
    }

    return __retval;
}

int32_t replace_hmac(int8_t* __pathname)
{
	uint8_t* __hmac  = NULL;
    int32_t __retval = ERROR;

    if((__hmac = (uint8_t*)malloc(HMAC256_LEN)) == NULL)
	{
		__retval = ERROR;
		goto out;
	}

	if(__get_signature(__pathname, __hmac))
	{
		if(__bdb_write_hmac(__strip_path(__pathname), __hmac))  // Overwrite Enabled ...
		{
			__retval = __add_to_profile(__hmac);
		}
	}
	else
	{
		fprintf(stderr, "Failed to generate signature for %s\n", __pathname);
	}

out:
	if(__hmac)
	{
		free(__hmac);
		__hmac = NULL;
	}

   return __retval;
}

int main(int ac, char** av)
{
    int32_t      __opt          = 0;
    extern char* optarg;
    int32_t      __retval       = ERROR;
    int32_t      __option_index = 0;
	static struct option __long_options[] = {
			{"add",    required_argument,  0, 'a' },
			{"delete", required_argument,  0, 'd' },
			{"replace", required_argument, 0, 'r' },
			{"help",   no_argument,        0, 'h' },
			{ 0,          0,               0,  0  }
        };


    if (getuid() != 0)
    {
        fprintf(stderr, "Only root can start/stop the fork connector\n");
        return 0;
    }

    __bdb_open();

    while((__opt = getopt_long(ac, av, "a:d:hr:",
                __long_options, &__option_index)) != -1)
	{
		switch(__opt)
		{
		case 'a':
			fprintf(stdout,"Inserting %s\n", optarg);
			__retval = insert_hmac((int8_t*)optarg);
			break;

		case 'd':
			fprintf(stdout,"Deleting %s\n", optarg);
			__retval = delete_hmac((int8_t*)optarg);
			break;

		case 'r':
			fprintf(stdout,"Replacing %s\n", optarg);
			__retval = replace_hmac((int8_t*)optarg);
			break;

		case 'h':
			fprintf(stdout, "usage: aerolock_addhmac --add <path/filename> --delete <filename> --replace <path/filename> -h\n");
			fprintf(stdout, "--add,    -a: Add a file to the system\n");
			fprintf(stdout, "--delete, -d: Delete a file from the system\n");
			fprintf(stdout, "--replace,-r: Replace an existing HMAC\n");
			fprintf(stdout, "--help,   -h This message\n");
			exit(0);

		default:
			break;
		}
	}

    __bdb_close();

    fprintf(stderr, "Operation %s\n", __retval ? "succeeded" : "failed");
    exit(__retval);
}
#ifdef __LINUX__
#pragma GCC diagnostic pop
#endif
