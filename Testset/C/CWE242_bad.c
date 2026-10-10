/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE242_Use_of_Inherently_Dangerous_Function__basic_02.c
Label Definition File: CWE242_Use_of_Inherently_Dangerous_Function__basic.label.xml
Template File: point-flaw-02.tmpl.c
*/
/*
 * @description
 * CWE: 242 Use of Inherently Dangerous Function
 * Sinks:
 *    GoodSink: Use fgets() for bounded user input
 *    BadSink : Use gets() for user input
 * Flow Variant: 02 Control flow: if(1) and if(0)
 *
 * */

#include "std_testcase.h"

#define DEST_SIZE 10


void CWE242_Use_of_Inherently_Dangerous_Function__basic_02_bad()
{
    if(1)
    {
        {
            char dest[DEST_SIZE];
            char *result;
            /* FLAW: gets is inherently dangerous and cannot be used safely. */
            /* INCIDENTAL CWE120 Buffer Overflow since gets is inherently dangerous and is
             * an unbounded copy. */
            result = gets(dest);
            /* Verify return value */
            if (result == NULL)
            {
                /* error condition */
                printLine("Error Condition: alter control flow to indicate action taken");
                exit(1);
            }
            dest[DEST_SIZE-1] = '\0';
            printLine(dest);
        }
    }
}



/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

