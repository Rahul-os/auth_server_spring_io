package com.example.auth_server_spring_io.keys;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.RSAKey;

@Component
public class KeyManager {
	
	public RSAKey rsaKey() {
		
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			g.initialize(2048);
			var kp = g.generateKeyPair();
			
			RSAPublicKey publickey = (RSAPublicKey) kp.getPublic();
			RSAPrivateCrtKey privatekey = (RSAPrivateCrtKey) kp.getPrivate();
			
			return new RSAKey.Builder(publickey)
					.privateKey(privatekey)
					.keyID(UUID.randomUUID().toString())
					.build();
		} catch (NoSuchAlgorithmException e) {
			
			throw new RuntimeException("Error occured!!");
		}
		
	}
}	
