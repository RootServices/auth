package integration.authorization.oauth2.grant.code.request.ValidateParams.validation;


import integration.authorization.oauth2.grant.code.request.ValidateParams.BaseTest;
import net.tokensmith.authorization.constant.ErrorCode;
import net.tokensmith.parser.exception.OptionalException;
import net.tokensmith.repository.entity.Client;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;


public class RedirectUriTest extends BaseTest {

    public Map<String, List<String>> makeParams(UUID clientId) {
        Map<String, List<String>> p = super.makeParams();
        p.get("client_id").add(clientId.toString());
        p.get("response_type").add("CODE");

        return p;
    }

    @Test
    public void redirectUriIsBlankStringShouldThrowInformResourceOwnerException() throws Exception {
        Client c = loadConfidentialClient();

        Map<String, List<String>> p = makeParams(c.getId());
        p.get("redirect_uri").add("");

        Exception cause = new OptionalException();

        runExpectInformResourceOwnerException(p, cause, 1);
    }

    @Test
    public void redirectUrisHasTwoItemsShouldThrowInformResourceOwnerException() throws Exception {
        Client c = loadConfidentialClient();

        Map<String, List<String>> p = makeParams(c.getId());
        p.get("redirect_uri").add(c.getRedirectURI().toString());
        p.get("redirect_uri").add(c.getRedirectURI().toString());

        Exception cause = new OptionalException();

        runExpectInformResourceOwnerException(p, cause, 1);
    }

    @Test
    public void redirectUriIsInvalidShouldThrowInformResourceOwnerException() throws Exception {
        Client c = loadConfidentialClient();

        Map<String, List<String>> p = makeParams(c.getId());
        p.get("redirect_uri").add("invalid-uri");

        runExpectInformResourceOwnerExceptionNoCause(p, 1);
    }

    public void redirectUriIsNotHttpsShouldThrowInformResourceOwnerException() throws Exception {
        Client c = loadConfidentialClient();

        Map<String, List<String>> p = makeParams(c.getId());
        p.get("redirect_uri").add("http://tokensmith.net");

        Exception cause = new OptionalException();

        runExpectInformResourceOwnerException(p, cause, 1);
    }

    @Test
    public void redirectUriDoesNotMatchClientShouldThrowInformResourceOwnerException() throws Exception {
        Client c = loadConfidentialClient();

        Map<String, List<String>> p = makeParams(c.getId());
        p.get("redirect_uri").add("https://tokensmith.net/continue");

        int expectedErrorCode = ErrorCode.REDIRECT_URI_MISMATCH.getCode();

        runExpectInformResourceOwnerExceptionNoCause(p, expectedErrorCode);
    }
}
