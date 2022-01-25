package com.example.authserversample.utils;

import java.util.UUID;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

public class KeyGenerator {
    
    public static ECKey getECKeys(){
        
        try{
            return new ECKeyGenerator( Curve.P_256 )
                            .keyID( UUID.randomUUID().toString() )
                            .generate();
        }
        catch( Exception ex ){
            throw new IllegalStateException();
        }
    }
}
