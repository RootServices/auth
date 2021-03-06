package net.tokensmith.authorization.oauth2.grant.redirect.implicit.authorization.request.context;

import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.context.GetClientRedirectUri;
import net.tokensmith.repository.entity.Client;
import net.tokensmith.repository.exceptions.RecordNotFoundException;
import net.tokensmith.repository.repo.ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Created by tommackenzie on 5/16/16.
 */
@Component
public class GetPublicClientRedirectUri extends GetClientRedirectUri {

    @Autowired
    private ClientRepository clientRepository;

    public GetPublicClientRedirectUri() {
    }

    public GetPublicClientRedirectUri(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @Override
    public Client getClient(UUID clientId) throws RecordNotFoundException {
        return clientRepository.getById(clientId);
    }
}
