/*
 * @description Infinite loop - do{}while()
 *
 * */

package juliet.testcases.CWE835_Infinite_Loop;

import juliet.support.*;

public class CWE835_Infinite_Loop__do_01 extends AbstractTestCase 
{
    
    public void bad()
    {
        int i = 0;
    
        /* FLAW: Infinite Loop - do{} with no break point */
        do 
        {
            IO.writeLine(i);
            i = (i + 1) % 256;
        } while(i >= 0);
    }
    

    
    
    
    /* Below is the main(). It is only used when building this testcase on 
     * its own for testing or for building a binary to use in testing binary 
     * analysis tools. It is not used when compiling all the juliet.testcases as one 
     * application, which is how source code analysis tools are tested. 
	 */ 

}