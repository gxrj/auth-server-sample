package com.example.authserversample.auth.tokens;

import com.example.authserversample.auth.models.AgentCredentials;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AgentAuthToken extends UsernamePasswordAuthenticationToken {

    public AgentAuthToken( String principal, AgentCredentials credentials ){
        super( principal, credentials );
    }

    public AgentAuthToken( String principal, AgentCredentials credentials,
                           Collection< ? extends GrantedAuthority > authorities ){
        super( principal, credentials, authorities );
    }
}
