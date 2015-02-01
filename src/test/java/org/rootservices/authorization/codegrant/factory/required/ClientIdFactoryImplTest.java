package org.rootservices.authorization.codegrant.factory.required;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.rootservices.authorization.codegrant.factory.exception.ClientIdException;
import org.rootservices.authorization.codegrant.factory.required.ClientIdFactoryImpl;
import org.rootservices.authorization.codegrant.validator.RequiredParam;
import org.rootservices.authorization.codegrant.validator.exception.EmptyValueError;
import org.rootservices.authorization.codegrant.validator.exception.MoreThanOneItemError;
import org.rootservices.authorization.codegrant.validator.exception.NoItemsError;
import org.rootservices.authorization.codegrant.validator.exception.ParamIsNullError;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static junit.framework.TestCase.fail;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ClientIdFactoryImplTest {

    @Mock
    private RequiredParam mockRequiredParam;

    private ClientIdFactory subject;

    @Before
    public void setUp() {
        subject = new ClientIdFactoryImpl(mockRequiredParam);
    }

    @Test
    public void testMakeClientId() throws Exception {
        UUID expected = UUID.randomUUID();
        List<String> items = new ArrayList<>();
        items.add(expected.toString());

        when(mockRequiredParam.run(items)).thenReturn(true);

        UUID actual = subject.makeClientId(items);
        assertThat(actual).isEqualTo(expected);
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
            assertThat(e.getDomainCause() instanceof IllegalArgumentException).isEqualTo(true);
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
            assertThat(e.getDomainCause() instanceof EmptyValueError).isEqualTo(true);
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
            assertThat(e.getDomainCause() instanceof MoreThanOneItemError).isEqualTo(true);
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
            assertThat(e.getDomainCause() instanceof NoItemsError).isEqualTo(true);
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
            assertThat(e.getDomainCause() instanceof ParamIsNullError).isEqualTo(true);
        }
    }
}