/*
 * @description Infinite loop - while(true)
 *
 * */

package juliet_java;

import juliet.support.*;

public class CWE835_Infinite_Loop__while_true_01 extends AbstractTestCase 
{
    

    
    private void good1() 
    {
        int i = 0;

        while(true)
        {
            /* FIX: Add a break point for the loop if i = 10 */
            if (i == 10) 
            { 
                break; 
            }
            
            IO.writeLine(i);
            i++;
        }
    }
    
    public void good()  
    {
        good1();
    }    
    
    /* Below is the main(). It is only used when building this testcase on 
     * its own for testing or for building a binary to use in testing binary 
     * analysis tools. It is not used when compiling all the juliet.testcases as one 
     * application, which is how source code analysis tools are tested. 
	 */ 

}