package org.acme.auth;

import io.vertx.core.json.JsonObject;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.jboss.logging.annotations.Param;
import org.jboss.logging.annotations.Property;
import org.junit.jupiter.api.Timeout;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;

@Path("/auth")
public class LoginController {

    private static final String HOST = "http://localhost";
    private static final String PORT = "8080";
    private static final String URL = HOST + ":" + PORT;
    private static final String CLIENT_SECRET = "5tqMreYDQ1oOSHXG3ZXXNlcQMTceNVoP";

    @POST
    @Path("/login")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response login(@Param JsonObject json) {
        HttpResponse<String> response = null;
        String urlEncoded = "";
        HttpClient httpClient = null;
        try {
            httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
                    .sslContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                    .build();
            Map<String, String> map = new HashMap<>();
            map.put("grant_type", "password");
            map.put("username", json.getString("email"));
            map.put("password", json.getString("password"));
            map.put("client_secret", CLIENT_SECRET);
            map.put("client_id", "ibenj");
            urlEncoded = map.entrySet()
                    .stream()
                    .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
            HttpRequest request = HttpRequest.newBuilder()
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(urlEncoded))
                    .uri(new URI(URL + "/realms/negrdo/protocol/openid-connect/token"))
                    .build();
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (URISyntaxException e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } catch (IOException e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } catch (InterruptedException e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
        if(response.statusCode() == 400) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        } else if(response.statusCode() == 401) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        } else if(response.statusCode() == 404) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(response.body()).build();
    }
}
