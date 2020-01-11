package helpers.fixture.persistence.http;

import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.Param;
import com.ning.http.client.Response;
import helpers.fixture.FormFactory;
import helpers.fixture.exception.GetCsrfException;
import helpers.fixture.persistence.http.input.AuthEndpointProps;
import helpers.fixture.persistence.http.input.AuthEndpointPropsBuilder;
import net.tokensmith.otter.QueryStringToMap;
import net.tokensmith.repository.entity.ConfidentialClient;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

/**
 * Created by tommackenzie on 7/22/15.
 */
public class PostAuthorizationForm {
    public static final String UTF_8 = "UTF-8";
    private AsyncHttpClient httpDriver;
    private GetSessionAndCsrfToken getSessionAndCsrfToken;

    public PostAuthorizationForm(AsyncHttpClient httpDriver, GetSessionAndCsrfToken getSessionAndCsrfToken) {
        this.httpDriver = httpDriver;
        this.getSessionAndCsrfToken = getSessionAndCsrfToken;
    }

    @Deprecated
    public String run(ConfidentialClient confidentialClient, String baseURI, List<String> scopes, String email) throws IOException, ExecutionException, InterruptedException, URISyntaxException, GetCsrfException {
        AuthEndpointProps props = new AuthEndpointPropsBuilder()
                .confidentialClient(confidentialClient)
                .baseURI(baseURI)
                .scopes(scopes)
                .email(email)
                .build();

        return this.run(props);
    }

    public String run(AuthEndpointProps props) throws IOException, ExecutionException, InterruptedException, URISyntaxException, GetCsrfException {

        String authEndpoint = authEndpoint(props);

        Session session = getSessionAndCsrfToken.run(authEndpoint);
        List<Param> postData = FormFactory.makeLoginForm(props.getEmail(), session.getCsrfToken());

        ListenableFuture<Response> f = httpDriver
                .preparePost(authEndpoint)
                .setFormParams(postData)
                .setCookies(Arrays.asList(session.getSession()))
                .execute();

        Response response = f.get();

        URI location = new URI(response.getHeader("location"));
        QueryStringToMap queryStringToMap = new QueryStringToMap();
        Map<String, List<String>> params = queryStringToMap.run(
                Optional.of(location.getQuery())
        );

        return params.get("code").get(0);
    }

    public String authEndpoint(AuthEndpointProps props) throws IOException {
        String redirectURI = URLEncoder.encode(props.getConfidentialClient().getClient().getRedirectURI().toString(), UTF_8);
        StringBuilder authEndpointBuilder = new StringBuilder()
                .append(props.getBaseURI()).append("?")
                .append("client_id=").append(props.getConfidentialClient().getClient().getId().toString()).append("&")
                .append("response_type=").append(props.getConfidentialClient().getClient().getResponseTypes().get(0).getName()).append("&")
                .append("redirect_uri=").append(redirectURI).append("&")
                .append("scope=");

        for(String scope: props.getScopes()) {
            authEndpointBuilder.append(URLEncoder.encode(scope + " ", UTF_8));
        }

        // add extra params, maybe nonce, state, etc
        for(Map.Entry<String, List<String>> param: props.getParams().entrySet()) {
            for(String value: param.getValue()) {
                authEndpointBuilder
                    .append("&")
                    .append(param.getKey()).append("=").append(value);
            }
        }

        return authEndpointBuilder.toString();
    }
}
