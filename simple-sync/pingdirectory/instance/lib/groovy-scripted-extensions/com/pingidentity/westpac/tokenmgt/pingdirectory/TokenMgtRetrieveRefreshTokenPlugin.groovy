/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at
 * docs/licenses/cddl.txt
 * or http://www.opensource.org/licenses/cddl1.php.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at
 * docs/licenses/cddl.txt.  If applicable,
 * add the following below this CDDL HEADER, with the fields enclosed
 * by brackets "[]" replaced with your own identifying information:
 *      Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 *
 *      Copyright 2010-2020 Ping Identity Corporation
 */
package com.pingidentity.westpac.tokenmgt.pingdirectory;

import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;

import com.pingidentity.westpac.tokenmgt.pingdirectory.utilities.JwtUtilities;
import com.pingidentity.westpac.tokenmgt.pingdirectory.utilities.TokenMgtHelper;
import com.unboundid.directory.sdk.common.operation.UpdatableAddRequest;
import com.unboundid.directory.sdk.common.operation.UpdatableAddResult;
import com.unboundid.directory.sdk.common.types.ActiveOperationContext;
import com.unboundid.directory.sdk.common.types.Entry;
import com.unboundid.directory.sdk.common.types.UpdatableEntry;
import com.unboundid.directory.sdk.ds.config.PluginConfig;
import com.unboundid.directory.sdk.ds.scripting.ScriptedPlugin;
import com.unboundid.directory.sdk.ds.types.DirectoryServerContext;
import com.unboundid.directory.sdk.ds.types.PreParsePluginResult;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

/**
 * This class provides a simple example of a scripted plugin which will attempt
 * to prevent clients from interacting with a specified attribute. Any add,
 * compare, modify, modify DN, or search request which references the specified
 * attribute will be rejected, and the attribute will be automatically removed
 * from any search result entries to be returned. It has one configuration
 * argument:
 * <UL>
 * <LI>attribute -- The name or OID of the attribute to attempt to prevent the
 * user from accessing.</LI>
 * </UL>
 */
public final class TokenMgtExchangeCodePlugin extends ScriptedPlugin {

	private static final String CONFIG_MTLS_KEYSTORE_CA_LOCATION = "mtls-keystore-ca-location";

	private static final String CONFIG_MTLS_KEYSTORE_PASSWORD = "mtls-keystore-password";

	private static final String CONFIG_MTLS_KEYSTORE_LOCATION = "mtls-keystore-location";

	private static final String CONFIG_IGNORE_SSL_ERRORS = "ignore-ssl-errors";

	// The server context for the server in which this extension is running.
	private DirectoryServerContext serverContext;

	private String keystoreFileLocation;
	private String keystoreRootCAFileLocation;
	private String keystorePassword;

	private static String[] allowedProtocols = null;

	boolean isIgnoreSSLErrors = false;

	/**
	 * Creates a new instance of this plugin. All plugin implementations must
	 * include a default constructor, but any initialization should generally be
	 * done in the {@code initializePlugin} method.
	 */
	public TokenMgtExchangeCodePlugin() {

		Security.addProvider(new BouncyCastleProvider());

		allowedProtocols = new String[1];
		allowedProtocols[0] = "TLSv1.2";
	}

	/**
	 * Updates the provided argument parser to define any configuration arguments
	 * which may be used by this plugin. The argument parser may also be updated to
	 * define relationships between arguments (e.g., to specify required, exclusive,
	 * or dependent argument sets).
	 *
	 * @param parser The argument parser to be updated with the configuration
	 *               arguments which may be used by this plugin.
	 *
	 * @throws ArgumentException If a problem is encountered while updating the
	 *                           provided argument parser.
	 */
	@Override()
	public void defineConfigArguments(final ArgumentParser parser) throws ArgumentException {

		Character shortIdentifier_p = 'p';
		String longIdentifier_p = CONFIG_MTLS_KEYSTORE_PASSWORD;
		boolean required_p = true;
		int maxOccurrences_p = 1;
		String placeholder_p = "";
		String description_p = "PKCS12 keystore password used for MTLS.";

		parser.addArgument(new StringArgument(shortIdentifier_p, longIdentifier_p, required_p, maxOccurrences_p,
				placeholder_p, description_p));

		Character shortIdentifier_s = 's';
		String longIdentifier_s = CONFIG_MTLS_KEYSTORE_CA_LOCATION;
		boolean required_s = true;
		int maxOccurrences_s = 1;
		String placeholder_s = "/tmp/server-profile/scripts/postman/cert/public.cer";
		String description_s = "CA root file location used for MTLS.";

		parser.addArgument(new StringArgument(shortIdentifier_s, longIdentifier_s, required_s, maxOccurrences_s,
				placeholder_s, description_s));

		Character shortIdentifier_k = 'k';
		String longIdentifier_k = CONFIG_MTLS_KEYSTORE_LOCATION;
		boolean required_k = true;
		int maxOccurrences_k = 1;
		String placeholder_k = "/tmp/server-profile/scripts/postman/cert/network.p12";
		String description_k = "PKCS12 keystore file location used for MTLS.";

		parser.addArgument(new StringArgument(shortIdentifier_k, longIdentifier_k, required_k, maxOccurrences_k,
				placeholder_k, description_k));

		Character shortIdentifier_i = 'i';
		String longIdentifier_i = CONFIG_IGNORE_SSL_ERRORS;
		boolean required_i = false;
		int maxOccurrences_i = 1;
		String placeholder_i = "false";
		String description_i = "Ignore SSL errors.";

		parser.addArgument(new StringArgument(shortIdentifier_i, longIdentifier_i, required_i, maxOccurrences_i,
				placeholder_i, description_i));

	}

	/**
	 * Initializes this plugin.
	 *
	 * @param serverContext A handle to the server context for the server in which
	 *                      this extension is running.
	 * @param config        The general configuration for this plugin.
	 * @param parser        The argument parser which has been initialized from the
	 *                      configuration for this plugin.
	 *
	 * @throws LDAPException If a problem occurs while initializing this plugin.
	 */
	@Override()
	public void initializePlugin(final DirectoryServerContext serverContext, final PluginConfig config,
			final ArgumentParser parser) throws LDAPException {
		serverContext.debugInfo("Beginning plugin initialization");

		final StringArgument arg1 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_CA_LOCATION);
		this.keystoreRootCAFileLocation = arg1.getValue();

		final StringArgument arg2 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_LOCATION);
		this.keystoreFileLocation = arg2.getValue();

		final StringArgument arg3 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_PASSWORD);
		this.keystorePassword = arg3.getValue();

		final StringArgument arg4 = (StringArgument) parser.getNamedArgument(CONFIG_IGNORE_SSL_ERRORS);
		this.isIgnoreSSLErrors = (arg4 != null && arg4.toString().equalsIgnoreCase("true")) ? true : false;

		this.serverContext = serverContext;

	}

	/**
	 * Indicates whether the configuration contained in the provided argument parser
	 * represents a valid configuration for this extension.
	 *
	 * @param config              The general configuration for this plugin.
	 * @param parser              The argument parser which has been initialized
	 *                            with the proposed configuration.
	 * @param unacceptableReasons A list that can be updated with reasons that the
	 *                            proposed configuration is not acceptable.
	 *
	 * @return {@code true} if the proposed configuration is acceptable, or
	 *         {@code false} if not.
	 */
	@Override()
	public boolean isConfigurationAcceptable(final PluginConfig config, final ArgumentParser parser,
			final List<String> unacceptableReasons) {
		return true;
	}

	/**
	 * Attempts to apply the configuration contained in the provided argument
	 * parser.
	 *
	 * @param config               The general configuration for this plugin.
	 * @param parser               The argument parser which has been initialized
	 *                             with the new configuration.
	 * @param adminActionsRequired A list that can be updated with information about
	 *                             any administrative actions that may be required
	 *                             before one or more of the configuration changes
	 *                             will be applied.
	 * @param messages             A list that can be updated with information about
	 *                             the result of applying the new configuration.
	 *
	 * @return A result code that provides information about the result of
	 *         attempting to apply the configuration change.
	 */
	@Override()
	public ResultCode applyConfiguration(final PluginConfig config, final ArgumentParser parser,
			final List<String> adminActionsRequired, final List<String> messages) {

		ResultCode rc = ResultCode.SUCCESS;

		final StringArgument arg1 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_CA_LOCATION);
		this.keystoreRootCAFileLocation = arg1.getValue();

		final StringArgument arg2 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_LOCATION);
		this.keystoreFileLocation = arg2.getValue();

		final StringArgument arg3 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_PASSWORD);
		this.keystorePassword = arg3.getValue();

		return rc;
	}

	/**
	 * Performs any cleanup which may be necessary when this plugin is to be taken
	 * out of service.
	 */
	@Override()
	public void finalizePlugin() {
	}

	/**
	 * Performs any processing which may be necessary before the server starts
	 * processing for an add request.
	 *
	 * @param operationContext The context for the add operation.
	 * @param request          The add request to be processed. It may be altered if
	 *                         desired.
	 * @param result           The result that will be returned to the client if the
	 *                         plugin result indicates that processing on the
	 *                         operation should be interrupted. It may be altered if
	 *                         desired.
	 *
	 * @return Information about the result of the plugin processing.
	 */
	@Override()
	public PreParsePluginResult doPreParse(final ActiveOperationContext operationContext,
			final UpdatableAddRequest request, final UpdatableAddResult result) {

		UpdatableEntry entry = request.getEntry();

		String objectClass = entry.getAttribute("objectClass").get(0).getValue();

		if (!objectClass.equals("tokenMgt"))
			return PreParsePluginResult.SUCCESS;

		Entry parentEntry = null;

		String parentDN = getParentDN(entry.getDN());
		try {
			parentEntry = serverContext.getBackendForEntry(parentDN).getEntry(parentDN);

			if (parentEntry == null)
				throw new Exception("Parent entry is null.");

		} catch (Exception e) {
			Attribute tokenMgtLastStatusError = new Attribute("tokenMgtLastStatusError",
					"Error loading parent: " + e.getMessage());
			entry.addAttribute(tokenMgtLastStatusError);
			return PreParsePluginResult.SUCCESS;
		}

		if (!parentEntry.hasAttribute("tokenMgtConfigClientAssertionAudience")
				|| !parentEntry.hasAttribute("tokenMgtConfigClientAssertionJWK")
				|| !parentEntry.hasAttribute("tokenMgtConfigTokenEndpoint")) {
			Attribute tokenMgtLastStatusError = new Attribute("tokenMgtLastStatusError",
					"Parent missing configuration.");
			entry.addAttribute(tokenMgtLastStatusError);
			return PreParsePluginResult.SUCCESS;
		}

		// if the request is missing any of these attributes,
		// it will likely error downstream. The error is not handled here.
		if (!entry.hasAttribute("tokenMgtAuthCode") || !entry.hasAttribute("tokenMgtClientId")
				|| !entry.hasAttribute("tokenMgtExpectedNonce") || !entry.hasAttribute("tokenMgtRedirectURI")) {
			Attribute tokenMgtLastStatusError = new Attribute("tokenMgtLastStatusError",
					"Entry missing required information.");
			entry.addAttribute(tokenMgtLastStatusError);
			return PreParsePluginResult.SUCCESS;
		}

		String tokenMgtAuthCode = entry.getAttribute("tokenMgtAuthCode").get(0).getValue();
		String tokenMgtClientId = entry.getAttribute("tokenMgtClientId").get(0).getValue();
		String tokenMgtExpectedNonce = entry.getAttribute("tokenMgtExpectedNonce").get(0).getValue();
		String tokenMgtRedirectURI = entry.getAttribute("tokenMgtRedirectURI").get(0).getValue();

		String tokenMgtConfigClientAssertionAudience = parentEntry.getAttribute("tokenMgtConfigClientAssertionAudience")
				.get(0).getValue();
		String tokenMgtConfigClientAssertionJWK = parentEntry.getAttribute("tokenMgtConfigClientAssertionJWK").get(0)
				.getValue();
		String tokenMgtConfigTokenEndpoint = parentEntry.getAttribute("tokenMgtConfigTokenEndpoint").get(0).getValue();

		try {
			processCallback(entry, keystoreFileLocation, keystoreRootCAFileLocation, keystorePassword, tokenMgtAuthCode,
					tokenMgtClientId, tokenMgtRedirectURI, tokenMgtConfigClientAssertionAudience, tokenMgtExpectedNonce,
					tokenMgtConfigClientAssertionJWK, tokenMgtConfigTokenEndpoint, this.isIgnoreSSLErrors);
		} catch (Exception e) {
			Attribute tokenMgtLastStatusError = new Attribute("tokenMgtLastStatusError",
					"Error processing callback: " + e.getMessage());
			entry.addAttribute(tokenMgtLastStatusError);
			return PreParsePluginResult.SUCCESS;
		}

		return PreParsePluginResult.SUCCESS;

	}

	private static String getParentDN(String dn) {
		String parent = dn.substring(dn.indexOf(',') + 1);

		return parent;
	}

	public static void processCallback(UpdatableEntry entry, String keystoreFileLocation,
			String keystoreRootCAFileLocation, String keystorePassword, String code, String clientId,
			String redirectUri, String audience, String expectedNonce, String jwk, String tokenEndpoint,
			boolean isIgnoreSSLErrors) throws Exception {
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/x-www-form-urlencoded");
		headers.put("Accept", "application/json");

		String clientAuthenticationJWT = JwtUtilities.getClientJWTAuthentication(clientId, audience, jwk);

		String queryString = String.format(
				"code=%s&client_id=%s&grant_type=authorization_code&redirect_uri=%s&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=%s",
				code, clientId, redirectUri, clientAuthenticationJWT);

		JSONObject jsonRespObj = TokenMgtHelper.getHttpJSONResponse(tokenEndpoint, queryString, keystoreFileLocation,
				keystoreRootCAFileLocation, keystorePassword, allowedProtocols, isIgnoreSSLErrors);

		String accessToken = (jsonRespObj.containsKey("access_token")) ? jsonRespObj.get("access_token").toString()
				: null;
		String refreshToken = (jsonRespObj.containsKey("refresh_token")) ? jsonRespObj.get("refresh_token").toString()
				: null;
		String idToken = (jsonRespObj.containsKey("id_token")) ? jsonRespObj.get("id_token").toString() : null;

		String accessTokenJSON = TokenMgtHelper.getJWTJSON(accessToken);
		String idTokenJSON = TokenMgtHelper.getJWTJSON(idToken);

		TokenMgtHelper.addAttribute(entry, "tokenMgtAccessTokenJWT", accessToken);
		TokenMgtHelper.addAttribute(entry, "tokenMgtRefreshToken", refreshToken);
		TokenMgtHelper.addAttribute(entry, "tokenMgtIDTokenJWT", idToken);
		TokenMgtHelper.addAttribute(entry, "tokenMgtAccessTokenJSON", accessTokenJSON);
		TokenMgtHelper.addAttribute(entry, "tokenMgtIDTokenJSON", idTokenJSON);

	}


}
