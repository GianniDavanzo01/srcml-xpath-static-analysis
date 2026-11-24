/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE252_Unchecked_Return_Value__char_fprintf_14.c
Label Definition File: CWE252_Unchecked_Return_Value.label.xml
Template File: point-flaw-14.tmpl.c
*/
/*
 * @description
 * CWE: 252 Unchecked Return Value
 * Sinks: fprintf
 *    GoodSink: Check if fprintf() fails
 *    BadSink : Do not check if fprintf() fails
 * Flow Variant: 14 Control flow: if(globalFive==5) and if(globalFive!=5)
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif


void CWE252_Unchecked_Return_Value__char_fprintf_14_bad()
{
    if(globalFive==5)
    {
        /* FLAW: Do not check the return value */
        fprintf(stdout, "%s\n", "string");
    }
}



/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

