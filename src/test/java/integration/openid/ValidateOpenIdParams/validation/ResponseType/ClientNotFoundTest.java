package integration.openid.ValidateOpenIdParams.validation.ResponseType;

import helper.ValidateParamsAttributes;
import integration.openid.ValidateOpenIdParams.BaseTest;
import org.junit.Test;
import org.rootservices.authorization.constant.ErrorCode;
import org.rootservices.authorization.grant.code.protocol.authorization.request.buider.exception.StateException;
import org.rootservices.authorization.persistence.entity.ResponseType;
import org.rootservices.authorization.persistence.exceptions.RecordNotFoundException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;


public class ClientNotFoundTest extends BaseTest {
    private static String REDIRECT_URI = "https://rootservices.org";

    public ValidateParamsAttributes makeValidateParamsAttributes() {
        ValidateParamsAttributes p = new ValidateParamsAttributes();
        p.clientIds.add(UUID.randomUUID().toString());
        p.redirectUris.add(REDIRECT_URI);

        return p;
    }

    @Test
    public void responseTypeIsNullShouldThrowInformResourceOwnerException() throws StateException {
        ValidateParamsAttributes p = makeValidateParamsAttributes();
        p.responseTypes = null;
        RecordNotFoundException expectedDomainCause = new RecordNotFoundException();
        int errorCode = ErrorCode.CLIENT_NOT_FOUND.getCode();

        runExpectInformResourceOwnerException(p, expectedDomainCause, errorCode);
    }

    @Test
    public void responseTypeIsEmptyListShouldThrowInformResourceOwnerException() throws StateException {
        ValidateParamsAttributes p = makeValidateParamsAttributes();
        RecordNotFoundException expectedDomainCause = new RecordNotFoundException();
        int errorCode = ErrorCode.CLIENT_NOT_FOUND.getCode();

        runExpectInformResourceOwnerException(p, expectedDomainCause, errorCode);
    }

    @Test
    public void responseTypeIsInvalidShouldThrowInformResourceOwnerException() throws StateException {
        ValidateParamsAttributes p = makeValidateParamsAttributes();
        p.responseTypes.add("invalid-response-type");
        RecordNotFoundException expectedDomainCause = new RecordNotFoundException();
        int errorCode = ErrorCode.CLIENT_NOT_FOUND.getCode();

        runExpectInformResourceOwnerException(p, expectedDomainCause, errorCode);
    }

    @Test
    public void responseTypeHasTwoItemsShouldThrowInformResourceException() throws StateException {
        ValidateParamsAttributes p = makeValidateParamsAttributes();
        p.responseTypes.add(ResponseType.CODE.toString());
        p.responseTypes.add(ResponseType.CODE.toString());
        RecordNotFoundException expectedDomainCause = new RecordNotFoundException();
        int errorCode = ErrorCode.CLIENT_NOT_FOUND.getCode();

        runExpectInformResourceOwnerException(p, expectedDomainCause, errorCode);
    }

    @Test
    public void responseTypeIsBlankStringShouldThrowInformResourceOwnerException() throws StateException {
        ValidateParamsAttributes p = makeValidateParamsAttributes();
        p.responseTypes.add("");
        RecordNotFoundException expectedDomainCause = new RecordNotFoundException();
        int errorCode = ErrorCode.CLIENT_NOT_FOUND.getCode();

        runExpectInformResourceOwnerException(p, expectedDomainCause, errorCode);
    }
}
