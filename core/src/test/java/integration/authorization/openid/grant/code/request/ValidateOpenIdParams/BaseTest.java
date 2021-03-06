package integration.authorization.openid.grant.code.request.ValidateOpenIdParams;


import helper.fixture.persistence.openid.LoadCodeConfidentialClientWithOpenIdScope;
import net.tokensmith.authorization.exception.ServerException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformClientException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformResourceOwnerException;
import net.tokensmith.authorization.openId.grant.redirect.code.authorization.request.ValidateOpenIdCodeResponseType;
import net.tokensmith.repository.entity.Client;
import net.tokensmith.repository.entity.ConfidentialClient;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.fail;


/**
 * Created by tommackenzie on 3/1/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:spring-auth-test.xml")
@Transactional
public abstract class BaseTest {

    @Autowired
    private LoadCodeConfidentialClientWithOpenIdScope loadCodeConfidentialClientWithOpenIdScope;
    @Autowired
    protected ValidateOpenIdCodeResponseType subject;

    public Map<String, List<String>>  makeParams() {
        Map<String, List<String>> parameters = new HashMap<>();

        List<String> clientIds = new ArrayList<>();
        List<String> responseTypes = new ArrayList<>();
        List<String> redirectUris = new ArrayList<>();
        List<String> scopes = new ArrayList<>();
        List<String> states = new ArrayList<>();

        parameters.put("client_id", clientIds);
        parameters.put("response_type", responseTypes);
        parameters.put("redirect_uri", redirectUris);
        parameters.put("scope", scopes);
        parameters.put("state", states);

        return parameters;
    }

    public Client loadConfidentialClient() throws Exception {
        ConfidentialClient cc = loadCodeConfidentialClientWithOpenIdScope.run();
        return cc.getClient();
    }

    public void runExpectInformResourceOwnerException(Map<String, List<String>> p, Exception cause) {

        try {
            subject.run(p);
            fail("expected InformResourceOwnerException to be thrown");
        } catch (InformResourceOwnerException e) {
            assertThat(e.getCause(), instanceOf(cause.getClass()));
        } catch(InformClientException e) {
            fail("InformClientException was thrown. Expected, InformResourceOwnerException");
        } catch (ServerException e) {
            fail("ServerException was thrown. Expected, InformResourceOwnerException");
        }
    }

    public void runExpectInformResourceOwnerExceptionNoCause(Map<String, List<String>> p) {

        try {
            subject.run(p);
            fail("expected InformResourceOwnerException to be thrown");
        } catch (InformResourceOwnerException e) {
            assertThat(e.getCause(), is(nullValue()));
        } catch(InformClientException e) {
            fail("InformClientException was thrown. Expected, InformResourceOwnerException");
        } catch (ServerException e) {
            fail("ServerException was thrown. Expected, InformResourceOwnerException");
        }
    }

    public void runExpectInformClientExceptionWithState(Map<String, List<String>> p, Exception cause, int expectedErrorCode, String expectedError, String expectedDescription, URI expectedRedirect) {

        try {
            subject.run(p);
            fail("expected InformResourceOwnerException to be thrown");
        } catch (InformClientException e) {
            assertThat(e.getCause(), instanceOf(cause.getClass()));
            assertThat(e.getCode(), is(expectedErrorCode));
            assertThat(e.getError(), is(expectedError));
            assertThat(e.getDescription(), is(expectedDescription));
            assertThat(e.getRedirectURI(), is(expectedRedirect));
            assertThat(e.getState().isPresent(), is(true));
            assertThat(e.getState().get(), is(p.get("state").get(0)));
        } catch (InformResourceOwnerException e) {
            fail("InformResourceOwnerException was thrown. Expected, InformClientException");
        } catch (ServerException e) {
            fail("ServerException was thrown. Expected, InformClientException");
        }
    }

    public void runExpectInformClientException(Map<String, List<String>> p, Exception expectedDomainCause, int expectedErrorCode, String expectedError, String expectedDescription, URI expectedRedirect) {

        try {
            subject.run(p);
            fail("expected InformResourceOwnerException to be thrown");
        } catch (InformClientException e) {
            assertThat(e.getCause(), instanceOf(expectedDomainCause.getClass()));
            assertThat(e.getCode(), is(expectedErrorCode));
            assertThat(e.getError(), is(expectedError));
            assertThat(e.getRedirectURI(), is(expectedRedirect));
            assertThat(e.getState().isPresent(), is(false));
        } catch (InformResourceOwnerException e) {
            fail("InformResourceOwnerException was thrown. Expected, InformClientException");
        } catch (ServerException e) {
            fail("ServerException was thrown. Expected, InformClientException");
        }
    }

    public void runExpectInformClientExceptionWithStateNoCause(Map<String, List<String>> p, int expectedErrorCode, String expectedError, String expectedDescription, URI expectedRedirect) throws Exception {

        try {
            subject.run(p);
            fail("expected InformResourceOwnerException to be thrown");
        } catch (InformClientException e) {
            assertThat(e.getCause(), is(nullValue()));
            assertThat(e.getCode(), is(expectedErrorCode));
            assertThat(e.getError(), is(expectedError));
            assertThat(e.getDescription(), is(expectedDescription));
            assertThat(e.getRedirectURI(), is(expectedRedirect));
            assertThat(e.getState().isPresent(), is(true));
            assertThat(e.getState().get(), is(p.get("state").get(0)));
        } catch (InformResourceOwnerException e) {
            fail("InformResourceOwnerException was thrown. Expected, InformClientException");
        }
    }
}
