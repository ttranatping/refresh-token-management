package com.pingidentity.westpac.tokenmgt.pingdirectory.utilities;

import java.util.ArrayList;
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
			throw new Exception("Could not exchange code for access token - JSON parse error", e);
		}

	}

	public static void addAttribute(UpdatableEntry entry, String attributeName, String attributeValue) {

		if (entry == null || attributeValue == null)
			return;

		Attribute tokenMgtLastStatusError = new Attribute(attributeName, attributeValue);
		entry.addAttribute(tokenMgtLastStatusError);

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
}
