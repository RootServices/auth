package org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.required;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.rootservices.authorization.constant.ErrorCode;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.exception.ClientIdException;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.validator.RequiredParam;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.validator.exception.EmptyValueError;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.validator.exception.MoreThanOneItemError;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.validator.exception.NoItemsError;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.validator.exception.ParamIsNullError;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;


public class ClientIdFactoryTest {

    @Mock
    private RequiredParam mockRequiredParam;

    private ClientIdFactory subject;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new ClientIdFactory(mockRequiredParam);
    }

    @Test
    public void testMakeClientId() throws Exception {
        UUID expected = UUID.randomUUID();
        List<String> items = new ArrayList<>();
        items.add(expected.toString());

        when(mockRequiredParam.run(items)).thenReturn(true);

        UUID actual = subject.makeClientId(items);
        assertThat(actual, is(expected));
    }

    @Test
    public void testMakeClientIdNotAUuid() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {

        List<String> items = new ArrayList<>();
        items.add("not-a-uuid");

        when(mockRequiredParam.run(items)).thenReturn(true);

        try {
            subject.makeClientId(items);
            fail("ClientIdException was expected.");
        } catch (ClientIdException e) {
            assertThat(e.getCode(), is(ErrorCode.CLIENT_ID_DATA_TYPE.getCode()));
        }
    }

    @Test
    public void testMakeClientIdEmptyValueError() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {

        List<String> items = new ArrayList<>();
        items.add("");

        when(mockRequiredParam.run(items)).thenThrow(EmptyValueError.class);

        try {
            subject.makeClientId(items);
            fail("ClientIdException was expected.");
        } catch (ClientIdException e) {
            assertThat(e.getCause(), instanceOf(EmptyValueError.class));
            assertThat(e.getCode(), is(ErrorCode.CLIENT_ID_EMPTY_VALUE.getCode()));
        }
    }

    @Test
    public void testMakeClientIdMoreThanOneItemError() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {

        UUID uuid = UUID.randomUUID();
        List<String> items = new ArrayList<>();
        items.add(uuid.toString());
        items.add(uuid.toString());

        when(mockRequiredParam.run(items)).thenThrow(MoreThanOneItemError.class);

        try {
            subject.makeClientId(items);
            fail("ClientIdException was expected.");
        } catch (ClientIdException e) {
            assertThat(e.getCause(), instanceOf(MoreThanOneItemError.class));
            assertThat(e.getCode(), is(ErrorCode.CLIENT_ID_MORE_THAN_ONE_ITEM.getCode()));
        }
    }

    @Test
    public void testMakeClientIdNoItemsError() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {

        List<String> items = new ArrayList<>();

        when(mockRequiredParam.run(items)).thenThrow(NoItemsError.class);

        try {
            subject.makeClientId(items);
            fail("ClientIdException was expected.");
        } catch (ClientIdException e) {
            assertThat(e.getCause(), instanceOf(NoItemsError.class));
            assertThat(e.getCode(), is(ErrorCode.CLIENT_ID_EMPTY_LIST.getCode()));
        }
    }

    @Test
    public void testMakeClientIdParamIsNullError() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {

        List<String> items = null;

        when(mockRequiredParam.run(items)).thenThrow(ParamIsNullError.class);

        try {
            subject.makeClientId(items);
            fail("ClientIdException was expected.");
        } catch (ClientIdException e) {
            assertThat(e.getCause() instanceof ParamIsNullError, is(true));
            assertThat(e.getCode(), is(ErrorCode.CLIENT_ID_NULL.getCode()));
        }
    }
}