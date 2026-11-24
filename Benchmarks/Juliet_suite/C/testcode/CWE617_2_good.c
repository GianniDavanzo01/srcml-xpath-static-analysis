/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE617_Reachable_Assertion__connect_socket_34.c
Label Definition File: CWE617_Reachable_Assertion.label.xml
Template File: sources-sink-34.tmpl.c
*/
/*
 * @description
 * CWE: 617 Reachable Assertion
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Number greater than ASSERT_VALUE
 * Sinks:
 *    BadSink : Assert if n is less than or equal to ASSERT_VALUE
 * Flow Variant: 34 Data flow: use of a union containing two methods of accessing the same data (within the same function)
 *
 * */

#include "std_testcase.h"

#include <assert.h>

#define ASSERT_VALUE 5

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else /* NOT _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define IP_ADDRESS "127.0.0.1"
#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

typedef union
{
    int unionFirst;
    int unionSecond;
} CWE617_Reachable_Assertion__connect_socket_34_unionType;



/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    int data;
    CWE617_Reachable_Assertion__connect_socket_34_unionType myUnion;
    /* Initialize data */
    data = -1;
    /* FIX: Use a value greater than the assert value */
    data = ASSERT_VALUE+1;
    myUnion.unionFirst = data;
    {
        int data = myUnion.unionSecond;
        /* POTENTIAL FLAW: this assertion could trigger if n <= ASSERT_VALUE */
        assert(data > ASSERT_VALUE);
    }
}

void CWE617_Reachable_Assertion__connect_socket_34_good()
{
    goodG2B();
}


/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */
