/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE390_Error_Without_Action__fgets_wchar_t_03.c
Label Definition File: CWE390_Error_Without_Action__fgets.label.xml
Template File: point-flaw-03.tmpl.c
*/
/*
 * @description
 * CWE: 390 Detection of Error Condition Without Action
 * Sinks:
 *    GoodSink: Check if fgetws() failed and handle errors properly
 *    BadSink : Check to see if fgetws() failed, but do nothing about it
 * Flow Variant: 03 Control flow: if(5==5) and if(5!=5)
 *
 * */

#include "std_testcase.h"



/* good1() uses if(5!=5) instead of if(5==5) */
static void good1()
{
    if(5!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            /* By initializing dataBuffer, we ensure this will not be the
             * CWE 690 (Unchecked Return Value To NULL Pointer) flaw for fgetws() */
            wchar_t dataBuffer[100] = L"";
            wchar_t * data = dataBuffer;
            printWLine(L"Please enter a string: ");
            /* FIX: check the return value and handle errors properly */
            if (fgetws(data, 100, stdin) == NULL)
            {
                printWLine(L"fgetws failed!");
                exit(1);
            }
            printWLine(data);
        }
    }
}

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(5==5)
    {
        {
            /* By initializing dataBuffer, we ensure this will not be the
             * CWE 690 (Unchecked Return Value To NULL Pointer) flaw for fgetws() */
            wchar_t dataBuffer[100] = L"";
            wchar_t * data = dataBuffer;
            printWLine(L"Please enter a string: ");
            /* FIX: check the return value and handle errors properly */
            if (fgetws(data, 100, stdin) == NULL)
            {
                printWLine(L"fgetws failed!");
                exit(1);
            }
            printWLine(data);
        }
    }
}

void CWE390_Error_Without_Action__fgets_wchar_t_03_good()
{
    good1();
    good2();
}


/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

