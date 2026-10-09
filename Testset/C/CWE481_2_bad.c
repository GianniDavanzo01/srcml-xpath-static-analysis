/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE481_Assigning_Instead_of_Comparing__basic_12.c
Label Definition File: CWE481_Assigning_Instead_of_Comparing__basic.label.xml
Template File: point-flaw-12.tmpl.c
*/
/*
 * @description
 * CWE: 481 Assigning Instead of Comparing
 * Sinks:
 *    GoodSink: Comparing
 *    BadSink : Assigning instead of comparing
 * Flow Variant: 12 Control flow: if(globalReturnsTrueOrFalse())
 *
 * */

#include "std_testcase.h"


void CWE481_Assigning_Instead_of_Comparing__basic_12_bad()
{
    if(globalReturnsTrueOrFalse())
    {
        {
            int intRand = rand();
            /* FLAW: should be == and INCIDENTIAL CWE 571 Expression Is Always True */
            if(intRand = 5)
            {
                printLine("i was 5");
            }
        }
    }
    else
    {
        {
            int intRand = rand();
            /* FIX: used == instead of = */
            if(intRand == 5)
            {
                printLine("i was 5");
            }
        }
    }
}



/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

