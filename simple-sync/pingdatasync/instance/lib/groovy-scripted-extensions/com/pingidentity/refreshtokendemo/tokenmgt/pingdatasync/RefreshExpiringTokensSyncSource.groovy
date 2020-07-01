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
 *      Copyright 2011-2020 Ping Identity Corporation
 */
package com.pingidentity.refreshtokendemo.tokenmgt.pingdatasync;

import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

import com.pingidentity.refreshtokendemo.tokenmgt.pingdirectory.utilities.TokenMgtHelper;
import com.unboundid.directory.sdk.common.types.LogSeverity;
import com.unboundid.directory.sdk.common.types.UpdatableEntry;
import com.unboundid.directory.sdk.ds.types.SearchEntryPluginResult;
import com.unboundid.directory.sdk.sync.config.SyncSourceConfig;
import com.unboundid.directory.sdk.sync.scripting.ScriptedSyncSource;
import com.unboundid.directory.sdk.sync.types.ChangeRecord;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.SetStartpointOptions;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

public final class RefreshExpiringTokensSyncSource extends ScriptedSyncSource

{
	private static final String DEFAULT_PINGDIRECTORY_EXTERNALSERVER = "pingdirectory";
	private static final long DEFAULT_ADVANCED_NOTICE = 120L;
	private static final String CONST_DEFAULT_FILTER = "(&(tokenMgtRefreshToken=*)(!(tokenMgtLastStatusError=*))(%s:jsonObjectFilterExtensibleMatch:={ \"filterType\" : \"lessThan\", \"field\" : \"exp\", \"value\" : %s }))";
	private static final String CONFIG_REFRESH_ADVANCED_NOTICE_SECONDS = "refresh-advanced-notice-seconds";
	private static final String CONFIG_PINGDIRECTORY_EXTERNALSERVER_NAME = "pingdirectory-external-server-id";
	private static final String CONFIG_MTLS_KEYSTORE_CA_LOCATION = "mtls-keystore-ca-location";
	private static final String CONFIG_MTLS_KEYSTORE_PASSWORD = "mtls-keystore-password";
	private static final String CONFIG_MTLS_KEYSTORE_LOCATION = "mtls-keystore-location";

	private static final String CONFIG_IGNORE_SSL_ERRORS = "ignore-ssl-errors";
	// The server context which can be used for obtaining the server state,
	// logging, etc.
	private SyncServerContext serverContext;

	private String ldapExternalServerCfgObjectName = DEFAULT_PINGDIRECTORY_EXTERNALSERVER;

	private int initialConnections = 5;
	private int maxConnections = 20;

	private Long refreshAdvancePeriodSeconds = DEFAULT_ADVANCED_NOTICE;

	private LDAPConnectionPool ldapConnection = null;

	private String[] changeAttributeNames = null;

	private String keystoreFileLocation;
	private String keystoreRootCAFileLocation;
	private String keystorePassword;

	boolean isIgnoreSSLErrors = false;

	@Override
	public void defineConfigArguments(final ArgumentParser parser) throws ArgumentException {

		Character shortIdentifier_a = 'a';
		String longIdentifier_a = CONFIG_REFRESH_ADVANCED_NOTICE_SECONDS;
		boolean required_a = true;
		int maxOccurrences_a = 1;
		String placeholder_a = String.valueOf(DEFAULT_ADVANCED_NOTICE);
		String description_a = "Advanced notice for refreshing a token before it expires.";

		parser.addArgument(new StringArgument(shortIdentifier_a, longIdentifier_a, required_a, maxOccurrences_a,
				placeholder_a, description_a));

		Character shortIdentifier_p = 'p';
		String longIdentifier_p = CONFIG_PINGDIRECTORY_EXTERNALSERVER_NAME;
		boolean required_p = true;
		int maxOccurrences_p = 1;
		String placeholder_p = DEFAULT_PINGDIRECTORY_EXTERNALSERVER;
		String description_p = "PingDirectory external server ID.";

		parser.addArgument(new StringArgument(shortIdentifier_p, longIdentifier_p, required_p, maxOccurrences_p,
				placeholder_p, description_p));

		Character shortIdentifier_o = 'o';
		String longIdentifier_o = CONFIG_MTLS_KEYSTORE_PASSWORD;
		boolean required_o = true;
		int maxOccurrences_o = 1;
		String placeholder_o = "";
		String description_o = "PKCS12 keystore password used for MTLS.";

		parser.addArgument(new StringArgument(shortIdentifier_o, longIdentifier_o, required_o, maxOccurrences_o,
				placeholder_o, description_o));

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

	@Override
	public void initializeSyncSource(final SyncServerContext serverContext, final SyncSourceConfig config,
			final ArgumentParser parser) {
		this.serverContext = serverContext;

		final StringArgument arg1 = (StringArgument) parser.getNamedArgument(CONFIG_REFRESH_ADVANCED_NOTICE_SECONDS);
		try {
			this.refreshAdvancePeriodSeconds = Long.parseLong(arg1.getValue());
		} catch (NumberFormatException e) {
			this.refreshAdvancePeriodSeconds = DEFAULT_ADVANCED_NOTICE;
		}

		final StringArgument arg2 = (StringArgument) parser.getNamedArgument(CONFIG_PINGDIRECTORY_EXTERNALSERVER_NAME);
		this.ldapExternalServerCfgObjectName = arg2.getValue();

		LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
		connectionOptions.setAbandonOnTimeout(true);
		connectionOptions.setConnectTimeoutMillis(10000);
		connectionOptions.setResponseTimeoutMillis(10000);
		connectionOptions.setUseKeepAlive(true);

		try {
			ldapConnection = this.serverContext.getLDAPExternalServerConnectionPool(ldapExternalServerCfgObjectName,
					connectionOptions, initialConnections, maxConnections, true);
		} catch (LDAPException e) {
			this.serverContext.logMessage(LogSeverity.FATAL_ERROR,
					String.format("Unable to connect to external server: %s", ldapExternalServerCfgObjectName));

			final StringArgument arg3 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_CA_LOCATION);
			this.keystoreRootCAFileLocation = arg3.getValue();

			final StringArgument arg4 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_LOCATION);
			this.keystoreFileLocation = arg4.getValue();

			final StringArgument arg5 = (StringArgument) parser.getNamedArgument(CONFIG_MTLS_KEYSTORE_PASSWORD);
			this.keystorePassword = arg5.getValue();

			final StringArgument arg6 = (StringArgument) parser.getNamedArgument(CONFIG_IGNORE_SSL_ERRORS);
			this.isIgnoreSSLErrors = (arg6 != null && arg4.toString().equalsIgnoreCase("true")) ? true : false;
		}

		changeAttributeNames = new String[3];
		changeAttributeNames[0] = "tokenMgtExpiringToken";
		changeAttributeNames[1] = "tokenMgtExpiringTokenProcess";
		changeAttributeNames[2] = "objectClass";
	}

	@Override
	public String getCurrentEndpointURL() {
		return "ProcessExpiringTokens";
	}

	@Override
	public void setStartpoint(SetStartpointOptions options) throws EndpointException {
	}

	@Override
	public Serializable getStartpoint() {
		return null;
	}

	@Override
	public void listAllEntries(final BlockingQueue<ChangeRecord> outputQueue) throws EndpointException {

		this.serverContext.logMessage(LogSeverity.SEVERE_WARNING, "TokenMgt: listAllEntries");
		String baseDN = "ou=adr-clients,o=sync";

		Long compareEpochSeconds = Instant.now().getEpochSecond() + refreshAdvancePeriodSeconds;

		String filter = String.format(CONST_DEFAULT_FILTER, "tokenMgtAccessTokenJSON", compareEpochSeconds);
		this.serverContext.logMessage(LogSeverity.SEVERE_WARNING, String.format("TokenMgt: filter=%s", filter));
		SearchResult searchResult = null;
		try {
			searchResult = ldapConnection.search(baseDN, SearchScope.SUB, filter, new String[0]);
		} catch (LDAPSearchException e) {
			this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
					String.format("TokenMgt: issue querying=%s", e.getExceptionMessage()));
			return;
		}

		List<SearchResultEntry> searchEntries = searchResult.getSearchEntries();

		if (searchEntries != null) {
			this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
					String.format("TokenMgt: results found size=%s", searchResult.getSearchEntries().size()));
			for (SearchResultEntry searchEntry : searchEntries) {

				this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
						String.format("TokenMgt: adding change item, DN=%s", searchEntry.getDN()));

				ChangeRecord.Builder bldr = new ChangeRecord.Builder(ChangeType.MODIFY, searchEntry.getDN());

				bldr.changedAttributes(changeAttributeNames);
				bldr.addProperty("objectClass", "tokenMgt");
				bldr.changeTime(System.currentTimeMillis());

				ChangeRecord record = bldr.build();

				outputQueue.add(record);
			}
		}
	}

	@Override
	public void listAllEntries(final Iterator<String> inputLines, final BlockingQueue<ChangeRecord> outputQueue)
			throws EndpointException {
		listAllEntries(outputQueue);
	}

	@Override
	public List<ChangeRecord> getNextBatchOfChanges(int maxChanges, AtomicLong numStillPending)
			throws EndpointException {

		List<ChangeRecord> returnChangeRecords = new ArrayList<ChangeRecord>(maxChanges);

		if (numStillPending.intValue() > 0) {
			this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
					String.format("TokenMgt: there are still pending tasks=%s", numStillPending.intValue()));

			return returnChangeRecords;
		}

		this.serverContext.logMessage(LogSeverity.SEVERE_WARNING, "TokenMgt: listAllEntries");
		String baseDN = "ou=adr-clients,o=sync";

		Long compareEpochSeconds = Instant.now().getEpochSecond() + refreshAdvancePeriodSeconds;

		String filter = String.format(CONST_DEFAULT_FILTER, "tokenMgtAccessTokenJSON", compareEpochSeconds);
		this.serverContext.logMessage(LogSeverity.SEVERE_WARNING, String.format("TokenMgt: filter=%s", filter));
		SearchResult searchResult = null;
		try {
			searchResult = ldapConnection.search(baseDN, SearchScope.SUB, filter, new String[0]);
		} catch (LDAPSearchException e) {
			this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
					String.format("TokenMgt: issue querying=%s", e.getExceptionMessage()));
			return returnChangeRecords;
		}

		List<SearchResultEntry> searchEntries = searchResult.getSearchEntries();

		if (searchEntries != null) {
			this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
					String.format("TokenMgt: results found size=%s", searchResult.getSearchEntries().size()));
			for (SearchResultEntry searchEntry : searchEntries) {

				this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
						String.format("TokenMgt: adding change item, DN=%s", searchEntry.getDN()));

				ChangeRecord.Builder bldr = new ChangeRecord.Builder(ChangeType.MODIFY, searchEntry.getDN());

				bldr.changedAttributes(changeAttributeNames);
				bldr.addProperty("objectClass", "tokenMgt");
				bldr.changeTime(System.currentTimeMillis());

				ChangeRecord record = bldr.build();

				returnChangeRecords.add(record);
			}
		}

		return returnChangeRecords;
	}

	@Override
	public Entry fetchEntry(SyncOperation operation) throws EndpointException {

		ChangeRecord record = operation.getChangeRecord();

		String dn = record.getIdentifiableInfo().getRDNString().replaceAll("\\\\", "");
		this.serverContext.logMessage(LogSeverity.DEBUG, String.format("TokenMgt: dn: %s", dn));

		String clientObjectDN = getParentDN(dn);
		String filter = getFilter(dn);
		this.serverContext.logMessage(LogSeverity.DEBUG, String.format("TokenMgt: clientObjectDN: %s", clientObjectDN));
		this.serverContext.logMessage(LogSeverity.DEBUG, String.format("TokenMgt: filter: %s", filter));

		this.serverContext.logMessage(LogSeverity.DEBUG, String.format("TokenMgt: fetching entry, DN=%s", dn));

		Entry returnEntry = new Entry(dn);
		returnEntry.addAttribute("tokenMgtExpiringToken", "true");
		returnEntry.addAttribute("objectClass", "tokenMgt");

		try {
			SearchResultEntry entry = this.ldapConnection.getEntry(dn.toString(), "tokenMgtRefreshToken");
			if (entry == null)
				throw new Exception("Could not load entry");
			
			SearchResultEntry clientObjectEntry = this.ldapConnection.getEntry(clientObjectDN.toString(),
					"tokenMgtConfigClientAssertionAudience", "tokenMgtConfigClientAssertionJWK",
					"tokenMgtConfigTokenEndpoint", "ou");
			if (clientObjectEntry == null)
				throw new Exception("Could not load clientObjectEntry");

			if (!clientObjectEntry.hasAttribute("tokenMgtConfigClientAssertionAudience")
					|| !clientObjectEntry.hasAttribute("tokenMgtConfigClientAssertionJWK")
					|| !clientObjectEntry.hasAttribute("tokenMgtConfigTokenEndpoint")) {
				setError(returnEntry, "clientObjectEntry missing configuration.");				
				return returnEntry;
			}

			String refreshToken = entry.getAttributeValue("tokenMgtRefreshToken");

			String clientId = clientObjectEntry.getAttributeValue("ou");
			String audience = clientObjectEntry.getAttributeValue("tokenMgtConfigClientAssertionAudience");
			String tokenEndpoint = clientObjectEntry.getAttributeValue("tokenMgtConfigTokenEndpoint");
			String jwk = clientObjectEntry.getAttributeValue("tokenMgtConfigClientAssertionJWK");

			Map<String, String> refreshTokenResultMap = TokenMgtHelper.processRefreshToken(refreshToken,
					keystoreFileLocation, keystoreRootCAFileLocation, keystorePassword, clientId, audience, jwk,
					tokenEndpoint, isIgnoreSSLErrors);

			for(String key: refreshTokenResultMap.keySet())
			{
				if(refreshTokenResultMap.get(key) == null)
					continue;
				returnEntry.addAttribute(key, refreshTokenResultMap.get(key));
			}
			
			return returnEntry;

		} catch (Exception e) {
			setError(returnEntry, String.format("TokenMgt: did not fetch entry, DN=%s", dn));				
			return returnEntry;
		}
	}

	private static String getParentDN(String dn) {
		String parent = dn.substring(dn.indexOf(',') + 1);

		return parent;
	}

	private static String getFilter(String dn) {
		String parent = dn.substring(0, dn.indexOf(','));

		return parent;
	}

	private void setError(final Entry entry, String errorMsg) {
		Attribute tokenMgtLastStatusError = new Attribute("tokenMgtLastStatusError", errorMsg);
		entry.addAttribute(tokenMgtLastStatusError);
	}

	@Override
	public void acknowledgeCompletedOps(LinkedList<SyncOperation> completedOps) throws EndpointException {
	}

}