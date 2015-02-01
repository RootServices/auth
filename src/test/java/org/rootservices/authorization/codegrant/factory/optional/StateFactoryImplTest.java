package org.rootservices.authorization.codegrant.factory.optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.rootservices.authorization.codegrant.factory.exception.StateException;
import org.rootservices.authorization.codegrant.validator.OptionalParam;
import org.rootservices.authorization.codegrant.validator.exception.EmptyValueError;
import org.rootservices.authorization.codegrant.validator.exception.MoreThanOneItemError;
import org.rootservices.authorization.persistence.entity.Scope;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static junit.framework.TestCase.fail;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 2/1/15.
 */
@RunWith(MockitoJUnitRunner.class)
public class StateFactoryImplTest {

    @Mock
    private OptionalParam mockOptionalParam;

    private StateFactory subject;

    @Before
    public void setUp() {
        subject = new StateFactoryImpl(mockOptionalParam);
    }

    @Test
    public void testMakeState() throws MoreThanOneItemError, EmptyValueError, StateException {
        String expectedValue = "state";
        Optional<String> expected = Optional.ofNullable(expectedValue);

        List<String> items = new ArrayList<>();
        items.add(expectedValue);

        when(mockOptionalParam.run(items)).thenReturn(true);
        Optional<String> actual = subject.makeState(items);
        assertThat(actual).isEqualTo(expected);
    }

    @Test
    public void testMakeStateWhenStatesAreNull() throws MoreThanOneItemError, EmptyValueError, StateException {
        Optional<String> expected = Optional.ofNullable(null);

        List<String> items = null;

        when(mockOptionalParam.run(items)).thenReturn(true);
        Optional<String> actual = subject.makeState(items);
        assertThat(actual).isEqualTo(expected);
    }

    @Test
    public void testMakeScopesEmptyValueError() throws MoreThanOneItemError, EmptyValueError {

        List<String> items = new ArrayList<>();
        items.add("");

        when(mockOptionalParam.run(items)).thenThrow(EmptyValueError.class);

        try {
            subject.makeState(items);
            fail("StateException was expected.");
        } catch (StateException e) {
            assertThat(e.getDomainCause() instanceof EmptyValueError).isEqualTo(true);
        }
    }

    @Test
    public void testMakeScopesMoreThanOneItemError() throws MoreThanOneItemError, EmptyValueError {

        List<String> items = new ArrayList<>();
        items.add("Scope1");
        items.add("Scope2");

        when(mockOptionalParam.run(items)).thenThrow(MoreThanOneItemError.class);

        try {
            subject.makeState(items);
            fail("StateException was expected.");
        } catch (StateException e) {
            assertThat(e.getDomainCause() instanceof MoreThanOneItemError).isEqualTo(true);
        }
    }
}