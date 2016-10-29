package org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.optional;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.rootservices.authorization.constant.ErrorCode;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.exception.ScopesException;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.validator.OptionalParam;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.validator.exception.EmptyValueError;
import org.rootservices.authorization.oauth2.grant.redirect.shared.authorization.request.factory.validator.exception.MoreThanOneItemError;

import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.fail;
import static org.fest.assertions.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 2/1/15.
 */
public class ScopesFactoryTest {

    @Mock
    private OptionalParam mockOptionalParam;

    private ScopesFactory subject;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new ScopesFactory(mockOptionalParam);
    }

    @Test
    public void testMakeScopes() throws MoreThanOneItemError, EmptyValueError, ScopesException {
        List<String> expected = new ArrayList<>();
        expected.add("profile");

        List<String> items = new ArrayList<>();
        items.add(expected.get(0).toString());

        when(mockOptionalParam.run(items)).thenReturn(true);

        List<String> actual = subject.makeScopes(items);
        assertThat(actual).isEqualTo(expected);
    }

    @Test
    public void testMakeScopesWhenScopesAreNull() throws MoreThanOneItemError, EmptyValueError, ScopesException {
        List<String> expected = new ArrayList<>();
        List<String> items = null;

        when(mockOptionalParam.run(items)).thenReturn(true);

        List<String> actual = subject.makeScopes(items);
        assertThat(actual).isEqualTo(expected);
    }

    @Test
    public void testMakeScopesWhenScopesAreEmptyList() throws MoreThanOneItemError, EmptyValueError, ScopesException {
        List<String> expected = new ArrayList<>();
        List<String> items = new ArrayList<>();

        when(mockOptionalParam.run(items)).thenReturn(true);

        List<String> actual = subject.makeScopes(items);
        assertThat(actual).isEqualTo(expected);
    }

    @Test
    public void testMakeScopesEmptyValueError() throws MoreThanOneItemError, EmptyValueError {

        List<String> items = new ArrayList<>();
        items.add("");

        when(mockOptionalParam.run(items)).thenThrow(EmptyValueError.class);

        try {
            subject.makeScopes(items);
            fail("ScopesException was expected.");
        } catch (ScopesException e) {
            assertThat(e.getCause() instanceof EmptyValueError).isEqualTo(true);
            assertThat(e.getCode()).isEqualTo(ErrorCode.SCOPES_EMPTY_VALUE.getCode());
        }

    }

    @Test
    public void testMakeScopesMoreThanOneItemError() throws MoreThanOneItemError, EmptyValueError {

        List<String> items = new ArrayList<>();
        items.add("profile");
        items.add("profile");

        when(mockOptionalParam.run(items)).thenThrow(MoreThanOneItemError.class);

        try {
            subject.makeScopes(items);
            fail("ScopesException was expected.");
        } catch (ScopesException e) {
            assertThat(e.getCause() instanceof MoreThanOneItemError).isEqualTo(true);
            assertThat(e.getCode()).isEqualTo(ErrorCode.SCOPES_MORE_THAN_ONE_ITEM.getCode());
        }
    }
}
