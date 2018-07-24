import static java.io.File.separator;
import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.regex.Pattern.quote;
import static java.util.stream.Collectors.joining;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

// for a more comprehensive solution see http://keystore-explorer.org/
public class ImportTLSCert {

	public static String jre() {
		RuntimeMXBean mxbean = ManagementFactory.getPlatformMXBean(RuntimeMXBean.class);
		return mxbean.getBootClassPath().split(quote(separator)+"lib"+quote(separator)+"\\w+\\.jar",2)[0];
	}
	
	private static String tool(String tool) {
		String java = jre()+separator+"bin"+separator+tool;
		return new File(java).exists() ? java : java + ".exe";
	}
	
	private static Certificate getCertificate(String hostName, int port) throws NoSuchAlgorithmException, KeyManagementException, IOException, UnknownHostException, SSLPeerUnverifiedException {
		System.setProperty("javax.net.ssl.trustStore", "clienttrust");
		SSLContext ctx = SSLContext.getInstance("TLS");
		X509TrustManager tm = new X509TrustManager() {
		    public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {}
		    public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {}
		    public X509Certificate[] getAcceptedIssuers() {return null;}
		};
		ctx.init(null, new TrustManager[]{tm}, null);
		SSLSocketFactory ssf = ctx.getSocketFactory();
		Socket socket = ssf.createSocket(hostName, port);

		Certificate[] cchain = ((SSLSocket) socket).getSession().getPeerCertificates();
	    if(cchain.length != 1) throw new IllegalArgumentException("Expected 1 cert but got "+cchain.length);
		return cchain[0];
	}
	
	static Scanner scanIn = new Scanner(System.in);
	public static void main(String[] args) throws Exception {
		String host = readInput("HTTPS host");
		int port = Integer.valueOf(readInput("HTTPS port", "443"));
		Certificate cert = getCertificate(host, port); 
		
    	X509Certificate x509Certificate = (X509Certificate) cert;
    	System.out.println(x509Certificate.getSubjectDN());
    	String alias = readInput("alias", x509Certificate.getSubjectDN().getName().replaceAll("\\W", ""));
    	String keystore = readInput("keystore",  jre() + "/lib/security/cacerts".replace("/", separator));
    	System.out.println("the default password of the JVM is 'changeit'");
    	String storePass = readInput("storePass",  "changeit");
    	
    	File certFile = writeToFile(x509Certificate);
    	System.out.println(certFile);
    	//certFile.deleteOnExit();
		//importCert(keystore, storePass, alias, certFile.getAbsolutePath());
	}

	private static File writeToFile(Certificate certificate) throws IOException, CertificateEncodingException {
		final String NL = System.getProperty("line.separator");
		File ret = File.createTempFile("cert", ".txt");
		String encoded = Base64.getMimeEncoder(64, NL.getBytes()).encodeToString(certificate.getEncoded());
		Files.write(ret.toPath(), format("-----BEGIN CERTIFICATE-----%s%s%s-----END CERTIFICATE-----", NL,  encoded  ,NL).getBytes());
		return ret;
	}

	private static String readInput(String message, String defaultValue) {
		System.out.println(format("%s [%s]:", message, defaultValue));
		String ret = scanIn.nextLine();
		return ret.trim().isEmpty() ? defaultValue : ret;
	}
	
	private static String readInput(String message) {
		System.out.println(message+":");
		return scanIn.nextLine();
	}

	private static void importCert(String keystore, String storePass, String alias, String certFile) throws InterruptedException, IOException {
		List<String> cmd = asList(
				tool("keytool"),
				"-import",
				"-alias",
				alias,
				"-keystore",
				keystore,
				"-file",
				certFile,
				"-storePass",
				storePass,
				"-noprompt",
				"-v"
				);
		System.out.println(cmd.stream().collect(joining(" ")));
		new ProcessBuilder(cmd).inheritIO().start().waitFor();
	}
}