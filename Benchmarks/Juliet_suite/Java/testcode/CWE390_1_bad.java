/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE390_Error_Without_Action__mkdirs_02.java
Label Definition File: CWE390_Error_Without_Action.label.xml
Template File: point-flaw-02.tmpl.java
*/
/*
* @description
* CWE: 390 Detection of Error Condition Without Action
* Sinks: mkdirs
*    GoodSink: Throw Exception if newDirectory cannot be created
*    BadSink : Do nothing if newDirectory cannot be created
* Flow Variant: 02 Control flow: if(true) and if(false)
*
* */

package juliet.testcases.CWE390_Error_Without_Action;

import juliet.support.*;

import java.io.File;

public class CWE390_Error_Without_Action__mkdirs_02 extends AbstractTestCase
{
    public void bad() throws Throwable
    {
        if (true)
        {
            File newDirectory = null;
            if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
            {
                /* running on Windows */
                newDirectory = new File("C:\\lvl_1\\lvl_2\\lvl_3\\");
            }
            else
            {
                /* running on non-Windows */
                newDirectory = new File("/home/user/lvl_1/lvl_2/lvl_3/");
            }
            if (!newDirectory.mkdirs())
            {
                /* FLAW: do nothing if newDirectory cannot be created */
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