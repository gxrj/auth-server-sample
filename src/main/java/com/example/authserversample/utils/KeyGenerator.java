package com.example.authserversample.utils;

import java.util.UUID;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

public class KeyGenerator {
    
    public static ECKey getECKeys(){
        
        try{
            return new ECKeyGenerator( Curve.P_256 )
                            .keyID( UUID.randomUUID().toString() )
                            .keyUse( KeyUse.SIGNATURE )
                            .algorithm( new Algorithm( SignatureAlgorithm.ES256.toString() , Requirement.RECOMMENDED ) )
                            .generate();
        }
        catch( Exception ex ){
            throw new IllegalStateException();
        }
    }
}
