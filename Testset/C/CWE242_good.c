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



/* good1() uses if(0) instead of if(1) */
static void good1()
{
    if(0)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            char dest[DEST_SIZE];
            char *result;
            /* FIX: use fgets for bounded read from stdin*/
            result = fgets(dest, DEST_SIZE, stdin);
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

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(1)
    {
        {
            char dest[DEST_SIZE];
            char *result;
            /* FIX: use fgets for bounded read from stdin*/
            result = fgets(dest, DEST_SIZE, stdin);
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

void CWE242_Use_of_Inherently_Dangerous_Function__basic_02_good()
{
    good1();
    good2();
}


/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

