package common;

import static java.io.File.separator;
import static java.lang.String.format;
import static java.util.regex.Pattern.quote;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class CertHelper {

	private static SSLSocketFactory getPermissveSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
		System.setProperty("javax.net.ssl.trustStore", "clienttrust");
		SSLContext ctx = SSLContext.getInstance("TLS");
		X509TrustManager tm = new X509TrustManager() {
			public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
			}
			
			public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
			}
			
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		};
		ctx.init(null, new TrustManager[] { tm }, null);
		return ctx.getSocketFactory();
	}
	
	public static String jre() {
		RuntimeMXBean mxbean = ManagementFactory.getPlatformMXBean(RuntimeMXBean.class);
		return mxbean.getBootClassPath().split(quote(separator) + "lib" + quote(separator) + "\\w+\\.jar", 2)[0];
	}

	public static File currentJREsCaCerts() {
		return new File(jre(), "lib/security/cacerts");
	}

	public static Certificate[] getTlsCertificate(String hostName, int port)
			throws NoSuchAlgorithmException, KeyManagementException, IOException, UnknownHostException, SSLPeerUnverifiedException {
		SSLSocketFactory ssf = getPermissveSSLSocketFactory();
		
		SSLSocket socket = (SSLSocket) ssf.createSocket(hostName, port);

		return socket.getSession().getPeerCertificates();
	}
	
	public static Certificate getTlsCertificateFromProxy(String proxyHost, int proxyPort)
			throws NoSuchAlgorithmException, KeyManagementException, IOException, UnknownHostException, SSLPeerUnverifiedException {
		SSLSocketFactory ssf = getPermissveSSLSocketFactory();

		String host = "example.com";
		int port = 443;
		
		InetSocketAddress proxyAddr = new InetSocketAddress(proxyHost, proxyPort);
        Socket underlying = new Socket(new Proxy(Proxy.Type.HTTP, proxyAddr));
        underlying.connect(new InetSocketAddress(host, port));
        SSLSocket socket = (SSLSocket) ssf.createSocket(
                underlying,
                proxyHost,
                proxyPort,
                true);
		
        Certificate[] cchain = socket.getSession().getPeerCertificates();
		if (cchain.length != 1)
			throw new IllegalArgumentException("Expected 1 cert but got " + cchain.length);
		return cchain[0];
	}

	public static KeyStore loadCaCerts(File cacerts, char[] password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore ks = KeyStore.getInstance("JKS");
		try (FileInputStream in = new FileInputStream(cacerts)) {
			ks.load(in, password);
			return ks;
		}
	}

	public static X509Certificate loadX509(InputStream inputStream) throws CertificateException {
		return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
	}

	public static void store(Certificate cert, File file) throws CertificateEncodingException, IOException {
		Files.write(file.toPath(), cert.getEncoded());
	}

	public static void storeBase64(Certificate cert, File file) throws CertificateEncodingException, IOException {
		final String NL = System.getProperty("line.separator");
		String encoded = Base64.getMimeEncoder(64, NL.getBytes()).encodeToString(cert.getEncoded());
		Files.write(file.toPath(), format("-----BEGIN CERTIFICATE-----%s%s%s-----END CERTIFICATE-----", NL, encoded, NL).getBytes());
	}
}