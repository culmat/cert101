import static java.io.File.separator;
import static java.util.regex.Pattern.quote;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.URL;
import java.security.KeyStore;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class Client {
	public static String jre() {
		RuntimeMXBean mxbean = ManagementFactory.getPlatformMXBean(RuntimeMXBean.class);
		return mxbean.getBootClassPath().split(quote(separator)+"lib"+quote(separator)+"\\w+\\.jar",2)[0];
	}
	
	public static void main(String[] args) throws Exception {
		File cacerts = new File(jre(),"lib/security/cacerts");
		cacerts = new File("cacertsWithSpark");
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(cacerts), "changeit".toCharArray());
		
//		X509Certificate cert =   (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream("spark.crt"));
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
		
		ks.store(new FileOutputStream("cacertsWithSpark"), "changeit".toCharArray());
	}

}
