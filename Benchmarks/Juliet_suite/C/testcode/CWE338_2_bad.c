/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE338_Weak_PRNG__w32_15.c
Label Definition File: CWE338_Weak_PRNG__w32.label.xml
Template File: point-flaw-15.tmpl.c
*/
/*
 * @description
 * CWE: 338 Use of Cryptographically Weak PRNG
 * Sinks:
 *    GoodSink: Use CryptGenRandom() to generate a random number
 *    BadSink : Use rand() to generate a random number
 * Flow Variant: 15 Control flow: switch(6)
 *
 * */

#include "std_testcase.h"

#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")


void CWE338_Weak_PRNG__w32_15_bad()
{
    switch(6)
    {
    case 6:
    {
        /* FLAW: Use of rand() as a PRNG */
        int data = rand();
        printIntLine(data);
    }
    break;
    default:
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
        break;
    }
}



/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

