package org.rootservices.authorization.oauth2.grant.redirect.authorization.request.factory.required;

import org.rootservices.authorization.constant.ErrorCode;
import org.rootservices.authorization.oauth2.grant.redirect.authorization.request.factory.exception.ResponseTypeException;
import org.rootservices.authorization.oauth2.grant.redirect.authorization.request.factory.validator.RequiredParam;
import org.rootservices.authorization.oauth2.grant.redirect.authorization.request.factory.validator.exception.EmptyValueError;
import org.rootservices.authorization.oauth2.grant.redirect.authorization.request.factory.validator.exception.MoreThanOneItemError;
import org.rootservices.authorization.oauth2.grant.redirect.authorization.request.factory.validator.exception.NoItemsError;
import org.rootservices.authorization.oauth2.grant.redirect.authorization.request.factory.validator.exception.ParamIsNullError;
import org.rootservices.authorization.persistence.entity.ResponseType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Created by tommackenzie on 1/31/15.
 */
@Component
public class ResponseTypeFactory {

    @Autowired
    RequiredParam requiredParam;

    public ResponseTypeFactory() {}

    public ResponseTypeFactory(RequiredParam requiredParam) {
        this.requiredParam = requiredParam;
    }

    public ResponseType makeResponseType(List<String> responseTypes) throws ResponseTypeException {

        try {
            requiredParam.run(responseTypes);
        } catch (EmptyValueError e) {
            throw new ResponseTypeException(ErrorCode.RESPONSE_TYPE_EMPTY_VALUE, "invalid_request", e);
        } catch (MoreThanOneItemError e) {
            throw new ResponseTypeException(ErrorCode.RESPONSE_TYPE_MORE_THAN_ONE_ITEM, "invalid_request", e);
        } catch (NoItemsError e) {
            throw new ResponseTypeException(ErrorCode.RESPONSE_TYPE_EMPTY_LIST, "invalid_request", e);
        } catch (ParamIsNullError e) {
            throw new ResponseTypeException(ErrorCode.RESPONSE_TYPE_NULL, "invalid_request", e);
        }

        ResponseType rt;
        try {
            rt = ResponseType.valueOf(responseTypes.get(0).toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ResponseTypeException(ErrorCode.RESPONSE_TYPE_DATA_TYPE, "unsupported_response_type", e);
        }

        return rt;
    }
}