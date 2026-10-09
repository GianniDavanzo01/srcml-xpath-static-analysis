public /* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE209_Information_Leak_Error__printStackTrace_02.java
Label Definition File: CWE209_Information_Leak_Error.label.xml
Template File: point-flaw-02.tmpl.java
*/
/*
* @description
* CWE: 209 Information exposure through error message
* Sinks: printStackTrace
*    GoodSink: Print generic error message to console
*    BadSink : Print stack trace to console
* Flow Variant: 02 Control flow: if(true) and if(false)
*
* */

package juliet.testcases.CWE209_Information_Leak_Error;

import juliet.support.*;

public class CWE209_Information_Leak_Error__printStackTrace_02 extends AbstractTestCase
{
    public void bad() throws Throwable
    {
        if (true)
        {
            try
            {
                throw new UnsupportedOperationException();
            }
            catch (UnsupportedOperationException exceptUnsupportedOperation)
            {
                exceptUnsupportedOperation.printStackTrace(); /* FLAW: Print stack trace to console on error */
            }
        }
    }

    /* good1() changes true to false */


    /* good2() reverses the bodies in the if statement */




    /* Below is the main(). It is only used when building this testcase on
     * its own for testing or for building a binary to use in testing binary
     * analysis tools. It is not used when compiling all the juliet.testcases as one
     * application, which is how source code analysis tools are tested.
     */

}
