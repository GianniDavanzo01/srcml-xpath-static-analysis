/*
 * @description Infinite Loop - while()
 * 
 * */

#include "std_testcase.h"



static void good1() 
{
    int i = 0;

    while(i >= 0)
    {
        /* FIX: Add a break point for the loop if i = 10 */
        if (i == 10) 
        { 
            break; 
        }
        printIntLine(i);
        i = (i + 1) % 256;
    }
}

void CWE835_Infinite_Loop__while_01_good() 
{
    good1();
}


/* Below is the main(). It is only used when building this testcase on 
 * its own for testing or for building a binary to use in testing binary 
 * analysis tools. It is not used when compiling all the testcases as one 
 * application, which is how source code analysis tools are tested. 
 */

