/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE321_Hard_Coded_Cryptographic_Key__basic_02.java
Label Definition File: CWE321_Hard_Coded_Cryptographic_Key__basic.label.xml
Template File: sources-sink-02.tmpl.java
*/
/*
* @description
* CWE: 321 Hard coded crypto key
* BadSource:  Set data to a hardcoded value
* GoodSource: Read data from the console using readLine()
* BadSink:  Use data as a cryptographic key
* Flow Variant: 02 Control flow: if(true) and if(false)
*
* */

package juliet.testcases.CWE321_Hard_Coded_Cryptographic_Key;

import juliet.support.*;

import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;

import java.util.logging.Level;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public class CWE321_Hard_Coded_Cryptographic_Key__basic_02 extends AbstractTestCase
{
    /* uses badsource and badsink */
    public void bad() throws Throwable
    {
        String data;
        if (true)
        {
            /* FLAW: Set data to a hardcoded value */
            data = "23 ~j;asn!@#/>as";
        }
        else
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = null;
        }

        if (data != null)
        {
            String stringToEncrypt = "Super secret Squirrel";
            byte[] byteStringToEncrypt = stringToEncrypt.getBytes("UTF-8");
            /* POTENTIAL FLAW: Use data as a cryptographic key */
            SecretKeySpec secretKeySpec = new SecretKeySpec(data.getBytes("UTF-8"), "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] byteCipherText = aesCipher.doFinal(byteStringToEncrypt);
            IO.writeLine(IO.toHex(byteCipherText)); /* Write encrypted data to console */
        }

    }

    /* goodG2B1() - use goodsource and badsink by changing true to false */


    /* goodG2B2() - use goodsource and badsink by reversing statements in if */




    /* Below is the main(). It is only used when building this testcase on
     * its own for testing or for building a binary to use in testing binary
     * analysis tools. It is not used when compiling all the juliet.testcases as one
     * application, which is how source code analysis tools are tested.
     */

}