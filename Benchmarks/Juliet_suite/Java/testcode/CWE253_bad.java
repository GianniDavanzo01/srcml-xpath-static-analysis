/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE253_Incorrect_Check_of_Function_Return_Value__FileInputStream_02.java
Label Definition File: CWE253_Incorrect_Check_of_Function_Return_Value__FileInputStream.label.xml
Template File: point-flaw-02.tmpl.java
*/
/*
* @description
* CWE: 253 Incorrect Check of Function Return Value
* Sinks:
*    GoodSink: Check the return value from FileInputStream.read() and handle possible errors
*    BadSink : Check the return value of FileInputStream.read() for the wrong value
* Flow Variant: 02 Control flow: if(true) and if(false)
*
* */

package juliet.testcases.CWE253_Incorrect_Check_of_Function_Return_Value;

import juliet.support.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;

import java.util.logging.Level;

public class CWE253_Incorrect_Check_of_Function_Return_Value__FileInputStream_02 extends AbstractTestCase
{
    public void bad() throws Throwable
    {
        if (true)
        {
            FileInputStream fis = null;
            try
            {
                int bytesToRead = 1024;
                byte[] byteArray = new byte[bytesToRead];
                fis = new FileInputStream("c:\\file.txt");
                /* FLAW: Incorrect check on result of read().  Should check if the return value is -1 or is less than bytesToRead. */
                if (fis.read(byteArray) == 0)
                {
                    IO.writeLine("Error reading file.");
                }
                else
                {
                    IO.writeLine(new String(byteArray, "UTF-8"));
                }
            }
            catch (FileNotFoundException exceptFileNotFound)
            {
                IO.logger.log(Level.WARNING, "FileNotFoundException opening file", exceptFileNotFound);
            }
            catch (IOException exceptIO)
            {
                IO.logger.log(Level.WARNING, "IOException reading file", exceptIO);
            }
            finally
            {
                try
                {
                    if (fis != null)
                    {
                        fis.close();
                    }
                }
                catch (IOException exceptIO)
                {
                    IO.logger.log(Level.WARNING, "IOException closing FileInputStream", exceptIO);
                }
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