/*
 * @description Infinite Loop - while()
 * 
 * */

#include "std_testcase.h"


void CWE835_Infinite_Loop__while_01_bad() 
{
    int i = 0;
    
    /* FLAW: Infinite Loop - while() with no break point */
    while(i >= 0)
    {
        printIntLine(i);
        i = (i + 1) % 256;
    }
}



/* Below is the main(). It is only used when building this testcase on 
 * its own for testing or for building a binary to use in testing binary 
 * analysis tools. It is not used when compiling all the testcases as one 
 * application, which is how source code analysis tools are tested. 
 */

