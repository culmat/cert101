package common;

import static common.CertHelper.currentJREsCaCerts;
import static common.CertHelper.loadCaCerts;
import static java.lang.String.format;
import static org.junit.Assert.assertEquals;
import static spark.Spark.get;
import static spark.Spark.secure;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import spark.Spark;
import spark.utils.IOUtils;

public class SSLTest {

	final static String message = "Hello Secure World";
	final static String path = "secureHello";
	final static int port = 4567;
	
	@BeforeClass
	public static void up()  throws Exception {
		secure("deploy/keystore.jks", "password", null, null);
        get("/"+path, (req, res) -> message);
	}
	
	
	@AfterClass
	public static void down() {
		Spark.stop();
	}
	
	private HttpsURLConnection getHttpsUrlConnection() throws IOException, MalformedURLException {
		return (HttpsURLConnection) new URL(format("https://localhost:%s/%s", port, path)).openConnection();
	}
	
	@Test(expected=SSLHandshakeException.class)
	public void testPlainFails() throws Exception {
		HttpsURLConnection yc = getHttpsUrlConnection();
		assertEquals(message, IOUtils.toString(yc.getInputStream()));
	}


	
	@Test
	public void testWithCertFromServers() throws Exception {
		KeyStore ks = loadCaCerts(currentJREsCaCerts(), "changeit".toCharArray());
		Certificate cert = CertHelper.getTlsCertificate("localhost", port);
		ks.setCertificateEntry("spark", cert);
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
		tmf.init(ks);
		TrustManager[] trustCerts = tmf.getTrustManagers();
		
		SSLContext sc = SSLContext.getInstance("TLSv1.2");
		sc.init(null, trustCerts, new java.security.SecureRandom());
		
		

		HttpsURLConnection yc = getHttpsUrlConnection();
		yc.setSSLSocketFactory(sc.getSocketFactory());
		assertEquals(message, IOUtils.toString(yc.getInputStream()));
		
	}
}
