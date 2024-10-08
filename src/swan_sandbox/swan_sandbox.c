#pragma GCC diagnostic ignored "-Wunused-const-variable"
#pragma GCC diagnostic ignored "-Wunused-value"
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <library.h>            // library_init()
#include <utils/chunk.h>        // chunk_hash_seed()
#include <utils/utils/object.h> // INIT()

#include <daemon.h> // libcharon_init()

static void libstrongswan_utils_chunk(void);
static void libstrongswan_utils_chunk(void);
static void libstrongswan_utils_utils_object(void);

int
main(int argc, char *argv[])
{
	int swan_sandbox_charon_main(int argc, char *argv[]);
	if (argc > 1 && strcmp(argv[1], "charon") == 0) {
		return swan_sandbox_charon_main(argc - 1, &argv[1]);
	}

	atexit(library_deinit);
	if (!library_init(NULL, "swan_sandbox")) {
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}

	atexit(libcharon_deinit);
	if (!libcharon_init())
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}


	libstrongswan_utils_chunk();
	libstrongswan_utils_utils_object();
}

// -----------------------------------------------------------------------------
// libstrongswan/utils/chunk.c

static void
libstrongswan_utils_chunk(void)
{
	// /dev/urandom read 16 bytes sizeof(hash_key)
	chunk_hash_seed();

	__asm__("nop");
}

// -----------------------------------------------------------------------------
// utils/utils/object.h
// https://docs.strongswan.org/docs/5.9/devs/objectOrientedC.html

typedef struct my_stack_t my_stack_t;

struct my_stack_t {

	/**
	 * Method "push" with one parameter and no return value
	 *
	 * @param i  element to push
	 */
	void (*push)(my_stack_t *this, int i);

	/**
	 * Method "add" with no parameters and no return value
	 */
	void (*add)(my_stack_t *this);

	/**
	 * Method "pop" with no parameters (except "this") and a return value
	 *
	 * @return   popped element
	 */
	int (*pop)(my_stack_t *this);
};

/**
 * Constructor
 *
 * @return     instance of my_stack_t
 */
my_stack_t *my_stack_create();

typedef struct private_my_stack_t private_my_stack_t;

struct private_my_stack_t {

	/**
	 * Public interface
	 */
	my_stack_t public;

	/**
	 * Internal stack items
	 */
#define MAX_STACK_SIZE 42
	int values[MAX_STACK_SIZE];

	/**
	 * Number of items
	 */
	int stack_size;
};

METHOD(my_stack_t, push, void, private_my_stack_t *this, int i)
{
	this->values[MAX_STACK_SIZE - ++this->stack_size] = i;
}

my_stack_t *
my_stack_create()
{
	private_my_stack_t *this;

	INIT(this,
		 .public =
			 {
				 .push = _push,
				 .add = NULL /* _add */,
				 .pop = NULL /* _pop */,
			 },
		 /* uninitialized fields are automatically set to zero */
	);

	/* return public part */
	return &this->public;
}

static void
libstrongswan_utils_utils_object(void)
{
	my_stack_t *my_stack = my_stack_create();
	__asm__("nop");
}
