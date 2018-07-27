import static common.CertHelper.currentJREsCaCerts;
import static common.CertHelper.loadCaCerts;
import static common.CertHelper.loadX509;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import common.CertHelper;

public class Client {
	
	public static void main(String[] args) throws Exception {
		File cacerts = currentJREsCaCerts();
		//cacerts = new File("cacertsWithSpark");
		KeyStore ks = loadCaCerts(cacerts, "changeit");
		
		FileInputStream inputStream = new FileInputStream("spark.crt");
		X509Certificate cert = loadX509(inputStream);
		
		CertHelper.store(cert, new File("sparkBla.cer"));
		
//		ks.setCertificateEntry("spark", cert);
		
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
		tmf.init(ks);
		TrustManager[] trustCerts = tmf.getTrustManagers();
		
		SSLContext sc = SSLContext.getInstance("TLSv1.2");
		sc.init(null, trustCerts, new java.security.SecureRandom());
		
		

		URL oracle = new URL("https://localhost:4567/secureHello");
		HttpsURLConnection yc = (HttpsURLConnection) oracle.openConnection();
		yc.setSSLSocketFactory(sc.getSocketFactory());
		BufferedReader in = new BufferedReader(new InputStreamReader(yc.getInputStream()));
		String inputLine;
		while ((inputLine = in.readLine()) != null)
			System.out.println(inputLine);
		in.close();
		
		//ks.store(new FileOutputStream("cacertsWithSpark"), "changeit".toCharArray());
	}


}
