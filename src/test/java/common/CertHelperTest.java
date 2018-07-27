package common;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;

import org.junit.Test;

public class CertHelperTest {

	@Test
	public void testLoadX509() throws Exception {
		try(InputStream in = new FileInputStream("spark.crt")) {
			X509Certificate certificate = CertHelper.loadX509(in);
			assertEquals("CN=localhost,OU=spark,O=spark,L=spark,ST=spark,C=UK", certificate.getIssuerX500Principal().getName());
		}
	}
	
	@Test
	public void testStoreLoadCycle() throws Exception {
		try(InputStream in = new FileInputStream("spark.crt")) {
			X509Certificate certificate1 = CertHelper.loadX509(in);
			File file = File.createTempFile("cert", ".txt");
			file.deleteOnExit();
			CertHelper.store(certificate1, file);
			try(InputStream in2 = new FileInputStream(file)) {
				X509Certificate certificate2 = CertHelper.loadX509(in2);
				assertEquals(certificate1, certificate2);
			}
		}
	}

}
