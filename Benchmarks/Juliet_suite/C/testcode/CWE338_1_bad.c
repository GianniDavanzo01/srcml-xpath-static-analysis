/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE338_Weak_PRNG__w32_03.c
Label Definition File: CWE338_Weak_PRNG__w32.label.xml
Template File: point-flaw-03.tmpl.c
*/
/*
 * @description
 * CWE: 338 Use of Cryptographically Weak PRNG
 * Sinks:
 *    GoodSink: Use CryptGenRandom() to generate a random number
 *    BadSink : Use rand() to generate a random number
 * Flow Variant: 03 Control flow: if(5==5) and if(5!=5)
 *
 * */

#include "std_testcase.h"

#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")


void CWE338_Weak_PRNG__w32_03_bad()
{
    if(5==5)
    {
        {
            /* FLAW: Use of rand() as a PRNG */
            int data = rand();
            printIntLine(data);
        }
    }
}



/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

