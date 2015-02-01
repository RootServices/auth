package org.rootservices.authorization.codegrant.factory.required;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.rootservices.authorization.codegrant.factory.exception.ResponseTypeException;
import org.rootservices.authorization.codegrant.validator.RequiredParam;
import org.rootservices.authorization.codegrant.validator.exception.EmptyValueError;
import org.rootservices.authorization.codegrant.validator.exception.MoreThanOneItemError;
import org.rootservices.authorization.codegrant.validator.exception.NoItemsError;
import org.rootservices.authorization.codegrant.validator.exception.ParamIsNullError;
import org.rootservices.authorization.persistence.entity.ResponseType;

import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.fail;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 2/1/15.
 */
@RunWith(MockitoJUnitRunner.class)
public class ResponseTypeFactoryImplTest {

    @Mock
    private RequiredParam mockRequiredParam;

    private ResponseTypeFactory subject;

    @Before
    public void setUp() {
        subject = new ResponseTypeFactoryImpl(mockRequiredParam);
    }

    @Test
    public void testMakeResponseType() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError, ResponseTypeException{
        ResponseType expected = ResponseType.CODE;

        List<String> items = new ArrayList<>();
        items.add(expected.toString());

        when(mockRequiredParam.run(items)).thenReturn(true);

        ResponseType actual = subject.makeResponseType(items);
        assertThat(actual).isEqualTo(expected);
    }

    @Test
    public void testMakeResponseTypeUnknownResponseType() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {
        List<String> items = new ArrayList<>();
        items.add("Unknown Response Type");

        when(mockRequiredParam.run(items)).thenReturn(true);

        try {
            subject.makeResponseType(items);
            fail("ResponseTypeException was expected.");
        } catch (ResponseTypeException e) {
            assertThat(e.getDomainCause() instanceof IllegalArgumentException).isEqualTo(true);
        }
    }

    @Test
    public void testMakeResponseTypeEmptyValueError() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {
        List<String> items = new ArrayList<>();
        items.add("");

        when(mockRequiredParam.run(items)).thenThrow(EmptyValueError.class);
        try {
            subject.makeResponseType(items);
            fail("ResponseTypeException was expected.");
        } catch (ResponseTypeException e) {
            assertThat(e.getDomainCause() instanceof EmptyValueError).isEqualTo(true);
        }
    }

    @Test
    public void testMakeResponseTypeMoreThanOneItemError() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {
        List<String> items = new ArrayList<>();
        items.add(ResponseType.CODE.toString());
        items.add(ResponseType.CODE.toString());

        when(mockRequiredParam.run(items)).thenThrow(MoreThanOneItemError.class);

        try {
            subject.makeResponseType(items);
            fail("ResponseTypeException was expected.");
        } catch (ResponseTypeException e) {
            assertThat(e.getDomainCause() instanceof MoreThanOneItemError).isEqualTo(true);
        }
    }

    @Test
    public void testMakeResponseTypeNoItemsError() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {
        List<String> items = new ArrayList<>();

        when(mockRequiredParam.run(items)).thenThrow(NoItemsError.class);

        try {
            subject.makeResponseType(items);
            fail("ResponseTypeException was expected.");
        } catch (ResponseTypeException e) {
            assertThat(e.getDomainCause() instanceof NoItemsError).isEqualTo(true);
        }
    }

    @Test
    public void testMakeResponseTypeParamIsNullError() throws NoItemsError, ParamIsNullError, MoreThanOneItemError, EmptyValueError {
        List<String> items = null;

        when(mockRequiredParam.run(items)).thenThrow(ParamIsNullError.class);
        try {
            subject.makeResponseType(items);
            fail("ResponseTypeException was expected.");
        } catch (ResponseTypeException e) {
            assertThat(e.getDomainCause() instanceof ParamIsNullError).isEqualTo(true);
        }
    }
}