package org.rootservices.authorization.codegrant.factory.required;

import org.rootservices.authorization.codegrant.factory.constants.ErrorCode;
import org.rootservices.authorization.codegrant.factory.constants.ValidationMessage;
import org.rootservices.authorization.codegrant.factory.exception.ClientIdException;
import org.rootservices.authorization.codegrant.validator.RequiredParam;
import org.rootservices.authorization.codegrant.validator.exception.EmptyValueError;
import org.rootservices.authorization.codegrant.validator.exception.MoreThanOneItemError;
import org.rootservices.authorization.codegrant.validator.exception.NoItemsError;
import org.rootservices.authorization.codegrant.validator.exception.ParamIsNullError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Created by tommackenzie on 1/31/15.
 */
@Component
public class ClientIdFactoryImpl implements ClientIdFactory {

    @Autowired
    RequiredParam requiredParam;

    public ClientIdFactoryImpl() {}

    public ClientIdFactoryImpl(RequiredParam requiredParam) {
        this.requiredParam = requiredParam;
    }

    public UUID makeClientId(List<String> items) throws ClientIdException {

        try {
            requiredParam.run(items);
        } catch (EmptyValueError e) {
            throw new ClientIdException(ValidationMessage.EMPTY_VALUE.toString(), ErrorCode.EMPTY_VALUE.getCode(), e);
        } catch (MoreThanOneItemError e) {
            throw new ClientIdException(ValidationMessage.MORE_THAN_ONE_ITEM.toString(), ErrorCode.MORE_THAN_ONE_ITEM.getCode(), e);
        } catch (NoItemsError e) {
            throw new ClientIdException(ValidationMessage.EMPTY_LIST.toString(), ErrorCode.EMPTY_LIST.getCode(), e);
        } catch (ParamIsNullError e) {
            throw new ClientIdException(ValidationMessage.NULL.toString(), ErrorCode.NULL.getCode(), e);
        }

        UUID uuid;
        try {
            uuid = UUID.fromString(items.get(0));
        } catch (IllegalArgumentException e) {
            throw new ClientIdException("Cannot coerce String to UUID", ErrorCode.DATA_TYPE.getCode(), e);
        }

        return uuid;
    }

}