/*
 * @description Infinite loop - for()
 *
 * */

package juliet.testcases.CWE835_Infinite_Loop;

import juliet.support.*;

public class CWE835_Infinite_Loop__for_01 extends AbstractTestCase 
{
    public void bad()
    {
        /* FLAW: Infinite Loop - for() with no break point */
        for (int i = 0; i >= 0; i = (i + 1) % 256)
        {
            IO.writeLine(i);
        }
    }
    

    

    
    
    
    /* Below is the main(). It is only used when building this testcase on 
     * its own for testing or for building a binary to use in testing binary 
     * analysis tools. It is not used when compiling all the juliet.testcases as one 
     * application, which is how source code analysis tools are tested. 
	 */ 

}