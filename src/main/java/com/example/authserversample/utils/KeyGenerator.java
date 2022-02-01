package com.example.authserversample.utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

public class KeyGenerator {
    
    public static ECKey getECKeys(){

        var ops = setKeyOperations( KeyOperation.SIGN, KeyOperation.VERIFY );
        
        try{
            return new ECKeyGenerator( Curve.P_256 )
                            .keyID( UUID.randomUUID().toString() )
                            .keyUse( KeyUse.SIGNATURE )
                            .algorithm( 
                                new Algorithm( 
                                    SignatureAlgorithm.ES256.toString(), 
                                    Requirement.RECOMMENDED ) 
                            )
                            .keyOperations( ops )
                            .generate();
        }
        catch( Exception ex ){
            throw new IllegalStateException();
        }
    }

    public static RSAKey getRsaKey() throws JOSEException {

        var operations = setKeyOperations( KeyOperation.SIGN, KeyOperation.VERIFY );

        return new RSAKeyGenerator( 2048 )
                            .keyID( UUID.randomUUID().toString() )
                            .keyUse( KeyUse.SIGNATURE )
                            .algorithm( 
                                new Algorithm( 
                                    SignatureAlgorithm.RS256.toString(), 
                                    Requirement.RECOMMENDED ) 
                            )
                            .keyOperations( operations )
                            .generate();
    }

    public static Set<KeyOperation> setKeyOperations( KeyOperation... operations ) {

        var operationsSet = new HashSet<KeyOperation>();
        var proceed = Collections.addAll( operationsSet, operations);

        var message = "Sign-keys generation could not set its operations.";
        message.concat( "Check KeyGenerator::setKeyOperations" );

        Assert.isTrue( proceed, message );

        return operationsSet;
    }

    public static JWK getEcJwk() 
    throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        KeyPairGenerator gen = KeyPairGenerator.getInstance( "EC" );
        gen.initialize( Curve.P_256.toECParameterSpec() );
        KeyPair pair = gen.generateKeyPair();
        
        return new ECKey.Builder( Curve.P_256 , ( ECPublicKey ) pair.getPublic() )
                        .privateKey( ( ECPrivateKey ) pair.getPrivate() )
                        .build();
    }

    public static JWK getRsaJwk() 
    throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        KeyPairGenerator gen = KeyPairGenerator.getInstance( "RSA" );
        gen.initialize( 2048 );
        KeyPair pair = gen.generateKeyPair();
        
        return new RSAKey.Builder( ( RSAPublicKey ) pair.getPublic() )
                        .privateKey( ( RSAPrivateKey ) pair.getPrivate() )
                        .keyID( UUID.randomUUID().toString() )
                        .keyUse( KeyUse.SIGNATURE )
                        .build();
    }
}
