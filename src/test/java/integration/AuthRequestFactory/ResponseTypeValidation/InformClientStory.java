package integration.AuthRequestFactory.ResponseTypeValidation;

import integration.AuthRequestFactory.steps.ResponseTypeValidation.InformClientSteps;
import integration.BaseStory;
import org.rootservices.authorization.codegrant.factory.AuthRequestFactory;
import org.rootservices.authorization.persistence.repository.ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Created by tommackenzie on 2/8/15.
 */
public class InformClientStory extends BaseStory<InformClientSteps> {

    @Autowired
    private AuthRequestFactory authRequestFactory;

    @Autowired
    private ClientRepository clientRepository;

    @Override
    public InformClientSteps makeSteps() {
        return new InformClientSteps(authRequestFactory, clientRepository);
    }
}