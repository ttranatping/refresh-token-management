package com.pingidentity.refreshtokendemo.tokenmgt.pingdirectory.utilities;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.unboundid.directory.sdk.common.types.UpdatableEntry;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;

public class TokenMgtHelper {
	private static JSONParser parser = new JSONParser();
	
	public static JSONObject getHttpJSONResponse(String tokenEndpoint, String data, String keystoreFileLocation,
			String keystoreRootCAFileLocation, String keystorePassword, String[] allowedProtocols, boolean isIgnoreSSLErrors) throws Exception {
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
		headers.put("Accept", "application/json");

		HttpResponseObj tokenRespObj;
		try {
			tokenRespObj = MASSLClient.executeHTTP(tokenEndpoint, "POST", headers, data, allowedProtocols,
					keystoreFileLocation, keystoreRootCAFileLocation, keystorePassword, "JKS", isIgnoreSSLErrors,
					30000);
		} catch (Exception e1) {
			throw new Exception("Could not exchange code for access token - unhandled exception", e1);
		}

		if (tokenRespObj.getStatusCode() != 200)
			throw new Exception(tokenRespObj.getResponseBody());

		String refToken = tokenRespObj.getResponseBody();

		if (refToken == null || refToken.trim().equals(""))
			throw new Exception("Could not exchange code for access token - empty response");

		JSONObject jsonRespObj = null;
		try {
			jsonRespObj = (JSONObject) parser.parse(refToken);
			return jsonRespObj;
		} catch (ParseException e) {
			throw new Exception(String.format("Could not exchange code for access token - JSON parse error: %s, %s", e.getMessage(), refToken));
		}

	}

	public static void addAttribute(UpdatableEntry entry, String attributeName, String attributeValue) {

		if (entry == null || attributeValue == null)
			return;

		Attribute tokenMgtLastStatusError = new Attribute(attributeName, attributeValue);
		entry.setAttribute(tokenMgtLastStatusError);

	}

	public static String getJWTJSON(String jwt) {
		if (jwt == null)
			return null;

		String[] jwtParts = jwt.split("\\.");

		if (jwtParts.length < 2)
			return null;

		byte[] decodedJSON = Base64.getDecoder().decode(jwtParts[1]);

		return new String(decodedJSON);
	}

	public static void addModification(List<Modification> mods, String attributeName, String attributeValue) {
		addModification(mods, attributeName, attributeValue, ModificationType.REPLACE);		
	}

	public static void addModification(List<Modification> mods, String attributeName, String attributeValue, ModificationType modType) {

		if (mods == null || attributeValue == null)
			return;
		
		Modification mod = new Modification(modType, attributeName, attributeValue);
		
		mods.add(mod);
		
	}

	public static Map<String, String> processRefreshToken(String refreshToken, String keystoreFileLocation,
			String keystoreRootCAFileLocation, String keystorePassword, String clientId,
			String audience, String jwk, String tokenEndpoint, boolean isIgnoreSSLErrors) throws Exception {


		String[] allowedProtocols = null;
		allowedProtocols = new String[1];
		allowedProtocols[0] = "TLSv1.2";
		
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
		headers.put("Accept", "application/json");

		String clientAuthenticationJWT = JwtUtilities.getClientJWTAuthentication(clientId, audience, jwk);

		String queryString = String.format(
				"refresh_token=%s&client_id=%s&grant_type=refresh_token&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=%s",
				refreshToken, clientId, clientAuthenticationJWT);

		JSONObject jsonRespObj = TokenMgtHelper.getHttpJSONResponse(tokenEndpoint, queryString, keystoreFileLocation,
				keystoreRootCAFileLocation, keystorePassword, allowedProtocols, isIgnoreSSLErrors);

		String accessToken = (jsonRespObj.containsKey("access_token")) ? jsonRespObj.get("access_token").toString()
				: null;
		String newRefreshToken = (jsonRespObj.containsKey("refresh_token")) ? jsonRespObj.get("refresh_token").toString()
				: refreshToken;
		String idToken = (jsonRespObj.containsKey("id_token")) ? jsonRespObj.get("id_token").toString() : null;

		String accessTokenJSON = TokenMgtHelper.getJWTJSON(accessToken);
		String idTokenJSON = TokenMgtHelper.getJWTJSON(idToken);
		
		Map<String, String> returnMap = new HashMap<String, String>();

		if(accessToken != null)
			returnMap.put("tokenMgtAccessTokenJWT", accessToken);
		
		if(newRefreshToken != null)
			returnMap.put("tokenMgtRefreshToken", newRefreshToken);

		if(idToken != null)
			returnMap.put("tokenMgtIDTokenJWT", idToken);

		if(accessTokenJSON != null)
			returnMap.put("tokenMgtAccessTokenJSON", accessTokenJSON);
		
		if(idTokenJSON != null)
			returnMap.put("tokenMgtIDTokenJSON", idTokenJSON);
		
		return returnMap;
	}
}

