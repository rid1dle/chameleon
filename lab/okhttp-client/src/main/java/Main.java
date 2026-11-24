import okhttp3.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

// Mirrors Suwayomi's NetworkHelper client (NetworkHelper.kt:51-125): default JSSE, OkHttp 5,
// UA set by an application interceptor. Cookie jar, cache and logging do not change what goes
// on the wire for one GET, so they are left out. The trust-all manager only accepts the lab's
// self-signed cert; it does not change the ClientHello.
public class Main {
  static final String UA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36";

  public static void main(String[] args) throws Exception {
    String ua = args.length > 1 ? args[1] : UA;
    X509TrustManager trustAll = new X509TrustManager() {
      public void checkClientTrusted(X509Certificate[] c, String a) {}
      public void checkServerTrusted(X509Certificate[] c, String a) {}
      public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    };
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, new TrustManager[]{trustAll}, null);
    OkHttpClient client = new OkHttpClient.Builder()
        .sslSocketFactory(ctx.getSocketFactory(), trustAll)
        .connectTimeout(30, TimeUnit.SECONDS)
        .addInterceptor(chain -> chain.proceed(chain.request().newBuilder().header("User-Agent", ua).build()))
        .build();
    // Optional third arg: a Cookie header, as Suwayomi replays FlareSolverr's cf_clearance (E1).
    Request.Builder req = new Request.Builder().url(args[0]);
    if (args.length > 2) req.header("Cookie", args[2]);
    try (Response r = client.newCall(req.build()).execute()) {
      System.err.println("STATUS " + r.code() + " cf-mitigated=" + r.header("cf-mitigated"));
      System.out.println(r.body().string());
    }
  }
}
