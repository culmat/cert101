import static spark.Spark.*;

public class Server {

    // View example at https://localhost:4567/secureHello

    public static void main(String[] args) {
        secure("deploy/keystore.jks", "password", null, null);
        get("/secureHello", (req, res) -> "Hello Secure World");
    }

}
