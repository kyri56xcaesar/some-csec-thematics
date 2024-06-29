#include <time.h>

#define log_decorator 20

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char *date; /* file access date */
	char *time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

    // File fingerprint: The digital fingerprint of the file the 
	// time the event occurred. 

	
};
