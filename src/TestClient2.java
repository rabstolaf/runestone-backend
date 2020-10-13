/* TestClient2.java
   Repeatedly send CPET protocol requests to CPET server.  
   Modified version 6/05 of Sender.java by RAB 1/99 
   Revised 7/18 to connect only once and reuse socket for all requests.
   Optional command-line flags:
     -q  quiet mode, no prompts or labels printed
     -ssl use SSL sockets
   Required command line args:  
     1.  name of host to connect to, 
     2.  port number to use. */

import java.io.*;
import java.net.*;
import javax.net.ssl.*;

public class TestClient2 {
  static String usage = "Usage:  java TestClient2 [-ssl] [-q] [host [port]]";
  static String defaultHost = "arachne.cs.stolaf.edu";
  static int defaultPort = 39801;
  static final int maxline = 10000;  
  static Socket outSock;
  static boolean verbose = true;

  static int getLine(byte [] buff) throws IOException {
    if (verbose) 
      System.out.println("Enter protocol command:");
    int count;  // to hold number of bytes read
    count = System.in.read(buff);
    /* assert:  input line stored in buff[0..count-1] */
    if (count == -1) {
      // end of input stream
      outSock.close();
      System.exit(0);
    }
    return count;
    
  }

  public static void main(String[] args) {
    boolean ssl = false;  /* governs whether SSL connection used */
    String host = null;  
    int port = 0;
    try {
      int index;
      for (index = 0;  index < args.length;  index++) {
	//System.out.println(index + ": " + args[index]);
	if (args[index].equals("-ssl"))
	  ssl = true;
	else if (args[index].equals("-q"))
	  verbose = false;
	else if (host == null) 
	  // first positional arg encountered
	  host = args[index];
	else if (port == 0) 
	  // second positional arg
	  port = Integer.parseInt(args[index]);
	else {
	  System.err.println(usage);
	  System.exit(1);
	}
      }
      /* flags and args parsed, with no leftovers */

      if (host == null) {
	if (verbose)
	  System.out.println("Using default host " + defaultHost);
	host = defaultHost;
      }
      if (port == 0) {
	if (verbose)
	  System.out.println("Using default port " + defaultPort);
	port = defaultPort;
      }
      /* host, port defined */
      
      if (verbose) 
	System.out.println("Initializing for network communication... ");
      if (ssl) {
	System.setProperty("javax.net.ssl.trustStore", "cpet.truststore");
	SSLSocketFactory sslFact =
	  (SSLSocketFactory) SSLSocketFactory.getDefault();
	outSock = (SSLSocket)sslFact.createSocket(host, port);
	SSLSocket sslOutSock = (SSLSocket) outSock;  // convenience
	String[] goodCipherSuites = { 
	  // intersection of Java 1.4.2 supported suites and 
	  // those avail in Mozilla (8/05)
	  "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	  "SSL_DHE_DSS_WITH_DES_CBC_SHA",
	  "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	  "SSL_DHE_RSA_WITH_DES_CBC_SHA",
	  "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
	  "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
	  "SSL_RSA_WITH_DES_CBC_SHA",
	  "SSL_RSA_WITH_RC4_128_MD5",
	  "SSL_RSA_WITH_RC4_128_SHA",
	  "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	  "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	  "TLS_RSA_WITH_AES_128_CBC_SHA",
	};
	sslOutSock.setEnabledCipherSuites(goodCipherSuites);
	sslOutSock.startHandshake();
      } else 
	outSock = new Socket(host, port);
      OutputStream outStream = outSock.getOutputStream();
      InputStream inStream = outSock.getInputStream();
      /* assert:  socket and streams initialized */
      
      byte[] outBuff = new byte[maxline], inBuff = new byte[maxline];
      int count;  // to hold number of bytes read
      while (true) {
	count = getLine(outBuff);  
	if (verbose)
	  System.out.println("  writing " + count + " bytes");
	outStream.write(outBuff, 0, count);  
	count = inStream.read(inBuff);
	if (verbose) 
	  System.out.print("  received " + count + " bytes:  ");
	System.out.print(new String(inBuff, 0, count));
	if (verbose)
	  System.out.println("");
	// outStream.flush();  // may be necessary in some contexts...
	
	if (outBuff[0] != '<') {
	  // old-style protocol command...
	  count = getLine(outBuff);  
	  if (verbose)
	    System.out.println("  writing " + count + " bytes");
	  outStream.write(outBuff, 0, count);  
	  count = inStream.read(inBuff);
	  if (verbose)
	    System.out.println("  received " + count + " bytes:  " + 
			     (count < 0 ? "" : new String(inBuff, 0, count)));
	  // outStream.flush();  // may be necessary in some contexts...
	  
	}
      }	
    }

    catch (IOException e) {
      System.err.println("TestClient2 failed.");
      System.err.println(e.getMessage());
      try { 
	outSock.close();
      } catch (IOException e2) {}
      System.exit(1);  // an error exit status
      return;
    }
  }
}


