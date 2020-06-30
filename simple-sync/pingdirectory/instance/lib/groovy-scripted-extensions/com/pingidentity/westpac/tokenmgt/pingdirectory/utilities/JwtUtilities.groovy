package com.pingidentity.westpac.tokenmgt.pingdirectory.utilities;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.UUID;

import org.json.simple.JSONObject;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

public class JwtUtilities {

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static String getUserPrincipal(String principalAttr, String jwt, String jwksUrl)
	{
		// Set up a JWT processor to parse the tokens and then check their
		// signature
		// and validity time window (bounded by the "iat", "nbf" and "exp"
		// claims)
		ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

		// The public RSA keys to validate the signatures will be sourced
		// from the
		// OAuth 2.0 server's JWK set, published at a well-known URL. The
		// RemoteJWKSet
		// object caches the retrieved keys to speed up subsequent look-ups
		// and can
		// also gracefully handle key-rollover
		JWKSource keySource = null;
		
		try {
			keySource = new RemoteJWKSet(new URL(
					jwksUrl));
		} catch (MalformedURLException e) {
			return null;
		}
		
		// The expected JWS algorithm of the access tokens (agreed out-of-band)
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.ES256;

		// Configure the JWT processor with a key selector to feed matching public
		// RSA keys sourced from the JWK set URL
		JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
		jwtProcessor.setJWSKeySelector(keySelector);

		// Process the token
		SecurityContext ctx = null; // optional context parameter, not required here
		JWTClaimsSet claimsSet;
		try {
			claimsSet = jwtProcessor.process(jwt, ctx);
		} catch (Exception e) {
			return null;
		}
		
		return claimsSet.getClaim(principalAttr).toString();
	}


	@SuppressWarnings("unchecked")
	public static String getClientJWTAuthentication(String clientId, String audience, String jwk) throws Exception {

		JSONObject base = new JSONObject();
		
		base.put("sub", clientId);
		
		try {
			String jwtRequest = getJWT(base, jwk, clientId, audience);

			return jwtRequest;

		} catch (Throwable e) {
			throw new Exception("Could not generate Intent Request JWT", e);
		}

	}

	private static String getJWT(JSONObject base, String jwk, String issuer, String audience) throws Throwable {
		JWK jwkObj = JWK.parse(jwk);

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner((RSAKey) jwkObj);

		Builder jwtBuilder = new JWTClaimsSet.Builder().issuer(issuer)
				.expirationTime(new Date(new Date().getTime() + 360 * 1000)).audience(audience).issueTime(new Date(new Date().getTime())).jwtID(UUID.randomUUID().toString());

		for (Object key : base.keySet())
			jwtBuilder.claim(key.toString(), base.get(key));

		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = jwtBuilder.build();

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.PS256), claimsSet);

		signedJWT.sign(signer);
		return signedJWT.serialize();
	}
}
