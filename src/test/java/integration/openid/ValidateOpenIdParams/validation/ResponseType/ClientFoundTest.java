package integration.openid.ValidateOpenIdParams.validation.ResponseType;

import helper.ValidateParamsAttributes;
import integration.openid.ValidateOpenIdParams.BaseTest;
import org.junit.Test;
import org.rootservices.authorization.constant.ErrorCode;
import org.rootservices.authorization.oauth2.grant.code.authorization.request.buider.exception.ResponseTypeException;
import org.rootservices.authorization.persistence.entity.Client;
import org.rootservices.authorization.persistence.entity.ResponseType;


public class ClientFoundTest extends BaseTest {

    @Test
    public void responseTypeIsNullShouldThrowInformClientException() throws Exception {
        Client c = loadClientWithOpenIdScope.run();

        ValidateParamsAttributes p = new ValidateParamsAttributes();
        p.clientIds.add(c.getUuid().toString());
        p.redirectUris.add(c.getRedirectURI().toString());
        p.responseTypes = null;

        Exception expectedDomainCause = new ResponseTypeException();
        int expectedErrorCode = ErrorCode.RESPONSE_TYPE_NULL.getCode();
        String expectedError = "invalid_request";

        runExpectInformClientException(p, expectedDomainCause, expectedErrorCode, expectedError, c.getRedirectURI());
    }

    @Test
    public void responseTypeIsEmptyListShouldThrowInformClientException() throws Exception {
        Client c = loadClientWithOpenIdScope.run();

        ValidateParamsAttributes p = new ValidateParamsAttributes();
        p.clientIds.add(c.getUuid().toString());
        p.redirectUris.add(c.getRedirectURI().toString());

        Exception expectedDomainCause = new ResponseTypeException();
        int expectedErrorCode = ErrorCode.RESPONSE_TYPE_EMPTY_LIST.getCode();
        String expectedError = "invalid_request";

        runExpectInformClientException(p, expectedDomainCause, expectedErrorCode, expectedError, c.getRedirectURI());

    }

    @Test
    public void responseTypeIsInvalidShouldThrowInformClientException() throws Exception {
        Client c = loadClientWithOpenIdScope.run();

        ValidateParamsAttributes p = new ValidateParamsAttributes();
        p.clientIds.add(c.getUuid().toString());
        p.redirectUris.add(c.getRedirectURI().toString());
        p.responseTypes.add("invalid-response-type");

        Exception expectedDomainCause = new ResponseTypeException();
        int expectedErrorCode = ErrorCode.RESPONSE_TYPE_DATA_TYPE.getCode();
        String expectedError = "unsupported_response_type";

        runExpectInformClientException(p, expectedDomainCause, expectedErrorCode, expectedError, c.getRedirectURI());
    }

    @Test
    public void responseTypeHasTwoItemsShouldThrowInformClientException() throws Exception {
        Client c = loadClientWithOpenIdScope.run();

        ValidateParamsAttributes p = new ValidateParamsAttributes();
        p.clientIds.add(c.getUuid().toString());
        p.redirectUris.add(c.getRedirectURI().toString());

        p.responseTypes.add(ResponseType.CODE.toString());
        p.responseTypes.add(ResponseType.CODE.toString());

        Exception expectedDomainCause = new ResponseTypeException();
        int expectedErrorCode = ErrorCode.RESPONSE_TYPE_MORE_THAN_ONE_ITEM.getCode();
        String expectedError = "invalid_request";

        runExpectInformClientException(p, expectedDomainCause, expectedErrorCode, expectedError, c.getRedirectURI());
    }

    @Test
    public void responseTypeIsBlankStringShouldThrowInformClientException() throws Exception {
        Client c = loadClientWithOpenIdScope.run();

        ValidateParamsAttributes p = new ValidateParamsAttributes();
        p.clientIds.add(c.getUuid().toString());
        p.redirectUris.add(c.getRedirectURI().toString());
        p.responseTypes.add("");

        Exception expectedDomainCause = new ResponseTypeException();
        int expectedErrorCode = ErrorCode.RESPONSE_TYPE_EMPTY_VALUE.getCode();
        String expectedError = "invalid_request";

        runExpectInformClientException(p, expectedDomainCause, expectedErrorCode, expectedError, c.getRedirectURI());
    }

    @Test
    public void responseTypesDontMatchShouldThrowInformClientException() throws Exception {
        Client c = loadClientWithOpenIdScope.run();

        ValidateParamsAttributes p = new ValidateParamsAttributes();
        p.clientIds.add(c.getUuid().toString());
        p.redirectUris.add(c.getRedirectURI().toString());
        p.responseTypes.add(ResponseType.TOKEN.toString());

        int expectedErrorCode = ErrorCode.RESPONSE_TYPE_MISMATCH.getCode();
        String expectedError = "unauthorized_client";

        runExpectInformClientExceptionNoCause(p, expectedErrorCode, expectedError, c.getRedirectURI());
    }
}
