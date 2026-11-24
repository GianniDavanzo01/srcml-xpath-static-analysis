/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE80_XSS__CWE182_Servlet_File_01.java
Label Definition File: CWE80_XSS__CWE182_Servlet.label.xml
Template File: sources-sink-01.tmpl.java
*/
/*
* @description
* CWE: 80 Cross Site Scripting (XSS)
* BadSource: File Read data from file (named c:\data.txt)
* GoodSource: A hardcoded string
* BadSink:  Display of data in web page after using replaceAll() to remove script tags, which will still allow XSS (CWE 182: Collapse of Data into Unsafe Value)
* Flow Variant: 01 Baseline
*
* */

package juliet.testcases.CWE80_XSS.s01;
import juliet.support.*;

import javax.servlet.http.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.File;
import java.io.IOException;

import java.util.logging.Level;

public class CWE80_XSS__CWE182_Servlet_File_01 extends AbstractTestCaseServlet
{
    /* uses badsource and badsink */


    public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        goodG2B(request, response);
    }

    /* goodG2B() - uses goodsource and badsink */
    private void goodG2B(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        /* FIX: Use a hardcoded string */
        data = "foo";

        if (data != null)
        {
            /* POTENTIAL FLAW: Display of data in web page after using replaceAll() to remove script tags, which will still allow XSS with strings like <scr<script>ipt> (CWE 182: Collapse of Data into Unsafe Value) */
            response.getWriter().println("<br>bad(): data = " + data.replaceAll("(<script>)", ""));
        }

    }

    /* Below is the main(). It is only used when building this testcase on
     * its own for testing or for building a binary to use in testing binary
     * analysis tools. It is not used when compiling all the juliet.testcases as one
     * application, which is how source code analysis tools are tested.
     */

}