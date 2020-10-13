/* Simple prototype server for CPET.  Server.java -- RAB 6/04
   Requires two command line args:  
     temp directory, for creation of any temp files for receptacles
     port number to use (on this machine). 
   Optional command-line flag:  
     -ssl , use SSL sockets
   Repeatedly 
     1.  accepts a new network connection, 
     2.  encapsulates that network connection in a thread that repeatedly 
         a.  reads a command represented as a protocol request,
	 b.  executes that command in a process and obtains standard output
             and standard error from that process, 
	 c.  writes standard output/error on the network connection,
	 d.  cleans up after that process,
         network connection and thread cleaned up when that connection ends.
*/

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.util.Date;
import java.util.Calendar;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Server {
  static final int maxInBuff = 10485760;  
  static final String interp = "./dispatch.py";  // command interpreter
  static String usage = "Usage:  java Server [-ssl] [tmpdir [port]]";
  static String defaultTmpdir = "/tmp";
  static int defaultPort = 39801;
  static private String prefix = "elDoom";
  
  /* verify that addr is an acceptable IP address */
  static boolean addressTest(byte[] addr) {
    return addr[0] == (byte)130 && addr[1] == 71; // && addr[2] == 32;
  }

  /** print a diagnostic message related to thread */
  static void printlnDiagnostic(ClientThread thread, String string) {
    System.out.println(diagnosticString(thread, string));
  }
  
  /** print a diagnostic message related to thread, without newline */
  static void printDiagnostic(ClientThread thread, String string) {
    System.out.print(diagnosticString(thread, string));
  }
  
  /* helper for diagnostic messages */
  private static String diagnosticString(ClientThread thread, String string) {
    return "[" + getTimestamp() + "] " + thread.getTidPrefix() + string;
  }

  /** return current timestamp, suitable for diagnostic messages */
  static String getTimestamp() {
    Calendar cal = Calendar.getInstance();
    String ts = Integer.toString(cal.get(Calendar.MONTH)+101).substring(1);
    ts += Integer.toString(cal.get(Calendar.DAY_OF_MONTH)+100).substring(1) +
      " ";
    ts += Integer.toString(cal.get(Calendar.HOUR_OF_DAY)+100).substring(1) +
      ":";
    ts += Integer.toString(cal.get(Calendar.MINUTE)+100).substring(1) + ":";
    ts += Integer.toString(cal.get(Calendar.SECOND)+100).substring(1);
    return  ts;
  }

  static String getSessionId(String str) {
    if (str.startsWith(prefix)) 
      return str.substring(prefix.length()+1);
    else 
      return null;
  }

  static boolean getPersistence(String str) {
    return str.startsWith(prefix) && 
      str.substring(prefix.length(), prefix.length()+1).equals("1");
  }

  /* algorithm to be performed by thread using sock for communication
     tmpdir is passed as arg to receptacles. */
  static void doProcess(Socket sock, String tmpdir, ClientThread thread) 
    throws IOException
  {
    InputStream inStream = sock.getInputStream();
    /* assert:  input socket and stream initialized */
    
    /* get socket information */
    SocketAddress remoteSA = sock.getRemoteSocketAddress();
    InetAddress remoteIA = 
      ((InetSocketAddress)remoteSA).getAddress();
    printDiagnostic(thread, "Connection succeeded.  Remote host:  ");
    System.out.print(remoteIA.getCanonicalHostName() + "(");
    byte[] remote = remoteIA.getAddress();
    for (int i = 0;  i < remote.length;  i++)
      System.out.print((i == 0 ? "" : ".") + 
		       (remote[i] < 0 ? 256 + remote[i]: remote[i]));
    System.out.println(")");
    Date rightnow = new Date();
    printlnDiagnostic(thread, rightnow.toString());
    if (!addressTest(remote)) {
      printlnDiagnostic(thread, "Unacceptable IP address -- refusing service");
      sock.close();
      return;
    }
    /* new connection is from an acceptable remote host */
    
    
    /* command loop for the persistent socket */
    do { 
      printlnDiagnostic(thread, "Obtaining command");
      byte[] inBuff = new byte[maxInBuff];
      int count = 0;  // to hold number of bytes recently read
      int pos = 0;  // holds index of next unused byte in inBuff
      int len = -1;  /* hold length of protocol string, 
			TEMPORARILY PASSED AS PREFIX TO PROTOCOL
			-1 before first read, 
			prefix 0 or missing means read only once */
      int start = 0;  /* to hold index of first byte after prefix */
            
      while ((pos < len || len < 0) && 
	     (count = inStream.read(inBuff, pos, maxInBuff - pos)) != -1) {
	if (len == -1) { // this was first read() call
	  len = 0;
	  int val;  // integer value of a byte
	  while ((val = Byte.valueOf(inBuff[start]).intValue()) >= 0x30 && 
		 val <= 0x39) {
	    len = 10*len + val - 0x30;
	    start++;
	  }
	  /* printlnDiagnostic(thread, "Prefix len is " + len + " = \"" + 
	     new String(inBuff, 0, start) + "\"");*/
	  int comment_start = start;
	  while (start < maxInBuff && 
		 Byte.valueOf(inBuff[start]).intValue() != 0x3c)
	    start++;
	  String comment = new String(inBuff, comment_start, 
				      start - comment_start);
	  printlnDiagnostic(thread, "Prefix comment is \"" + 
			    comment + "\" (" +(start-comment_start)+" bytes)");
	}
	// len holds int value of prefix, start holds index of first byte after
	if (count != -1)
	  pos += count;
      }

      if (count == -1) {
	printlnDiagnostic(thread, "End of socket input encountered, disconnecting");
	break;	  
      }

      if (pos == maxInBuff) 
	printlnDiagnostic(thread, "Warning:  command buffer filled");

      String command = new String(inBuff, start, pos);
      printDiagnostic(thread, "  Successfully received the following " + 
		      (pos - start) + " bytes:  ");
      System.out.println(command);
      printlnDiagnostic(thread, "  (" + (pos - start) + " bytes received)");
      /* successfully obtained command */
      
      OutputStream outStream = sock.getOutputStream();
      
      printlnDiagnostic(thread, "Executing command");
      Runtime runTime = Runtime.getRuntime();
      String arg;
      if (len > 0)
	arg = "" + len;
      else
	arg = command.trim();
      String arr[] = {interp, tmpdir, arg,};
      Process proc = runTime.exec(arr);
      if (len > 0) {
	printlnDiagnostic(thread, "Sending command to " + interp + 
			  " via stdin");
	BufferedOutputStream toProc = 
	  new BufferedOutputStream(proc.getOutputStream());
	toProc.write(inBuff, start, pos-start);
	toProc.close();
      }
      
      BufferedInputStream fromProc = 
	new BufferedInputStream(proc.getInputStream());
      String response = new String(); 
      int ct;
      count = 0;
      while ((ct = fromProc.read(inBuff, 0, maxInBuff)) != -1) {
	response = response + new String(inBuff, 0, ct); 
	count += ct;	
      }
      // count  bytes read from output stream from command, stored in  response

      printlnDiagnostic(thread, "Output from command (" 
			+ count + " bytes):  " 
			+ response);
      /* detect response from login protocol
         Server should be refactored so that every response has some protocol 
         to be stripped off before forwarding content to client, to allow 
         Server.java an option to postprocess like this.  RAB 1/06 */
      String sessionId;
      if ((sessionId = getSessionId(response)) != null) {
	if (getPersistence(response))
	  thread.setPersistent();  
	response = sessionId;
	printlnDiagnostic(thread, "login protocol message detected, " + 
			  "modified response == " + response);
      }
      
      BufferedInputStream errProc = 
	new BufferedInputStream(proc.getErrorStream());
      String errResponse = new String();
      int errCount = 0;
      while ((ct = errProc.read(inBuff, 0, maxInBuff)) != -1) {
	errResponse = errResponse + new String(inBuff, 0, ct); 
	errCount += ct;	
      }
      // errCount  bytes read from error stream, stored in  errResponse  

      printlnDiagnostic(thread, "Error stream from command (" 
			+ errCount + " bytes):  ");
      printlnDiagnostic(thread, errResponse);

      if (errCount > 0) {
	String header = "<cpet-response output-length=\"" + count +
	  "\" error-length=\"" + errCount + "\" />";
	printlnDiagnostic(thread, "Header:  " + header);
	response = header + response + errResponse;
      }
      // response holds bytes to send to client
      
      //OutputStream outStream = sock.getOutputStream();
      printlnDiagnostic(thread, "Sending response on socket (" + 
			response.length() + " bytes)");
      outStream.write(response.getBytes());
      
      /* cleaning up */
      //toProc.close();  // already done this
      fromProc.close();
      errProc.close();
      
      proc.destroy();
      try {
	proc.waitFor();
      } catch (InterruptedException e) {
	printlnDiagnostic(thread, "Command process has died");
      }
      
      try {
	printlnDiagnostic(thread, "Exit status from command:  " 
			  + proc.exitValue());
      } catch (IllegalThreadStateException e) {
	printlnDiagnostic(thread, "Couldn't collect exit status");
	printlnDiagnostic(thread, e.getMessage());
      }

    } while (thread.isPersistent());

    sock.close();
  }
  
  public static void main(String[] args) {
    int port = 0;
    String tmpdir = null;
    boolean ssl = false;  // set true to use ssl sockets
    boolean data_received;

    System.out.println("Using input buffer size " + maxInBuff);

    try {
      int index;
      for (index = 0;  index < args.length;  index++) {
	if (args[index].equals("-ssl"))
	  ssl = true;
	else if (tmpdir == null)  
	  // first positional arg encountered
	  tmpdir = args[index];
	else if (port == 0) 
	  // second positional arg
	  port = Integer.parseInt(args[index]);
	else {
	  System.err.println(usage);
	  System.exit(1);
	}
      }
      /* flags and args parsed, with no leftovers */

      if (tmpdir == null) {
	System.out.println("Using default tmpdir " + defaultTmpdir +
			   " for receptacles");
	tmpdir = defaultTmpdir;
      }
      if (port == 0) {
	System.out.println("Using default port " + defaultPort);
	port = defaultPort;
      }
      /* tmpdir, host defined */

      System.out.println("Initializing for network communication... ");
      ServerSocket servSock = null;
      if (ssl) {
	Security.insertProviderAt(new BouncyCastleProvider(),2);
	System.setProperty("javax.net.ssl.keyStore", 
			   "/cs/www/html/projects/cpet/auth/cpet.keystore");
	System.setProperty("javax.net.ssl.keyStorePassword", "tepCTepc");
	SSLServerSocketFactory sslServFact =
	  (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
	servSock =(SSLServerSocket)sslServFact.createServerSocket(port);
	SSLServerSocket sslServSock = (SSLServerSocket) servSock;// convenience

	String[] goodCipherSuites = { 
	  "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", // ted
	  "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",  // ted
	  "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",  // ted
	  "SSL_DH_anon_WITH_DES_CBC_SHA",  // ted
	  "SSL_DH_anon_WITH_RC4_128_MD5",  // ted
	  "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	  "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	  "SSL_DHE_DSS_WITH_DES_CBC_SHA",
	  "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	  "SSL_DHE_RSA_WITH_DES_CBC_SHA",
	  "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
	  "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
	  "SSL_RSA_WITH_DES_CBC_SHA",
	  "SSL_RSA_WITH_RC4_128_MD5",
	  "SSL_RSA_WITH_RC4_128_SHA",
	  "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	  "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	  "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	  "TLS_RSA_WITH_AES_128_CBC_SHA",
	};
	sslServSock.setEnabledCipherSuites(goodCipherSuites);
	//	sslServSock.setWantClientAuth(false);
      } else {
	servSock = new ServerSocket(port);
      }
      /* assert:  ServerSocket object successfully created */
      
      while (true) {
	
	System.out.println("************************************************");
	System.out.println("Waiting for an incoming connection... ");
	Socket sock;  
	if (ssl)
	  sock = (SSLSocket) servSock.accept();
	else
	  sock = servSock.accept();

	ClientThread thread = new ClientThread(sock, tmpdir);
	printlnDiagnostic(thread, "New thread constructed, about to .start()");
	thread.start();
	printlnDiagnostic(thread, "Done with .start()");
      }
    }
    catch (IOException e) {
      System.err.println("Server failed.");
      System.err.println(e.getMessage());
      System.exit(1);  // an error exit status
      return;
    }
  }
}

class ClientThread extends Thread {
  static int next = 0;
  int tid;
  Socket sock;  // socket to client
  String tmpdir;  // name of temp directory for receptacles
  boolean persistent = false; // records whether sock is a persistent socket

  public ClientThread(Socket so, String t) {
    sock = so;  tmpdir = t;  tid = next++;
  }

  public int getTid() { return tid; }

  public boolean isPersistent() { return persistent; }
 
  void setPersistent() { persistent = true; }

  public String getTidPrefix() { return tid + "> "; }

  public void run() {
    try {
      Server.doProcess(sock, tmpdir, this);
      
    } catch (IOException e) {
      System.err.println("ClientThread failed.");
      System.err.println(e.getMessage());
      return;
    }
  }
}
