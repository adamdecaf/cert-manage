import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.lang.RuntimeException;

public class Download {
    public static void main(String [] args) throws IOException {
        URL url = new URL("https://www.google.com/images/branding/product/ico/googleg_lodp.ico");
        HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
        httpConn.connect();

        InputStream is = httpConn.getInputStream();
        int size = 0;
        while (is.read() >= 0) {
            size += 1;
        }
        is.close();

        int responseCode = httpConn.getResponseCode();
        try {
            if (responseCode > 299) {
                throw new RuntimeException(String.format("Got %d http response code, expected 2xx", responseCode));
            } else {
                System.out.println(String.format("Successfully downloaded url, size=%d bytes", size));
            }
        } finally {
            httpConn.disconnect();
        }
    }
}
