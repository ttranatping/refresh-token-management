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
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.directory.sdk.common.types.LogSeverity;
import com.unboundid.directory.sdk.sync.config.SyncSourceConfig;
import com.unboundid.directory.sdk.sync.scripting.ScriptedSyncSource;
import com.unboundid.directory.sdk.sync.types.ChangeRecord;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.SetStartpointOptions;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

public final class ProcessExpiringTokensSyncSource extends ScriptedSyncSource

{
	private static final String DEFAULT_PINGDIRECTORY_EXTERNALSERVER = "pingdirectory";
	private static final long DEFAULT_ADVANCED_NOTICE = 120L;
	private static final String CONST_DEFAULT_FILTER = "(&(!(tokenMgtLastStatusError=*))(%s:jsonObjectFilterExtensibleMatch:={ \"filterType\" : \"lessThan\", \"field\" : \"exp\", \"value\" : %s }))";
	private static final String CONFIG_REFRESH_ADVANCED_NOTICE_SECONDS = "refresh-advanced-notice-seconds";
	private static final String CONFIG_PINGDIRECTORY_EXTERNALSERVER_NAME = "pingdirectory-external-server-id";
	// The server context which can be used for obtaining the server state,
	// logging, etc.
	private SyncServerContext serverContext;

	private String ldapExternalServerCfgObjectName = DEFAULT_PINGDIRECTORY_EXTERNALSERVER;

	private int initialConnections = 5;
	private int maxConnections = 20;

	private Long refreshAdvancePeriodSeconds = DEFAULT_ADVANCED_NOTICE;

	private LDAPConnectionPool ldapConnection = null;

	String[] changeAttributeNames = null;

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

		try {
			ldapConnection = this.serverContext.getLDAPExternalServerConnectionPool(ldapExternalServerCfgObjectName,
					connectionOptions, initialConnections, maxConnections, true);
		} catch (LDAPException e) {
			this.serverContext.logMessage(LogSeverity.FATAL_ERROR,
					String.format("Unable to connect to external server: %s", ldapExternalServerCfgObjectName));
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
		this.serverContext.logMessage(LogSeverity.SEVERE_WARNING, String.format("TokenMgt: dn: %s", dn));

		String parentDN = getParentDN(dn);
		String filter = getFilter(dn);
		this.serverContext.logMessage(LogSeverity.SEVERE_WARNING, String.format("TokenMgt: parent: %s", parentDN));
		this.serverContext.logMessage(LogSeverity.SEVERE_WARNING, String.format("TokenMgt: filter: %s", filter));

		this.serverContext.logMessage(LogSeverity.SEVERE_WARNING, String.format("TokenMgt: fetching entry, DN=%s", dn));

		Entry returnEntry = new Entry(dn);
		returnEntry.addAttribute("tokenMgtExpiringToken", "true");
		returnEntry.addAttribute("objectClass", "tokenMgt");

		try {
			SearchResultEntry entry = this.ldapConnection.getEntry(dn.toString(), "tokenMgtAccessTokenJWT", "tokenMgtLastStatusError");

			if (entry == null)
				throw new Exception("Could not load entry");

			String accessToken = entry.getAttributeValue("tokenMgtAccessTokenJWT");
			String tokenMgtLastStatusError = entry.getAttributeValue("tokenMgtLastStatusError");

			this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
					String.format("TokenMgt: fetched entry, access_token: %s", accessToken));

			returnEntry.addAttribute("tokenMgtExpiringTokenProcess", "true");
			
			if(tokenMgtLastStatusError != null)
				returnEntry.addAttribute("tokenMgtLastStatusError", tokenMgtLastStatusError);
			
			if(accessToken != null)
				returnEntry.addAttribute("tokenMgtAccessTokenJWT", accessToken);
				
			
		} catch (Exception e) {

			this.serverContext.logMessage(LogSeverity.SEVERE_WARNING,
					String.format("TokenMgt: did not fetch entry, DN=%s", dn));
			returnEntry.addAttribute("tokenMgtExpiringTokenProcess", "false");
		}

		return returnEntry;
	}

	private static String getParentDN(String dn) {
		String parent = dn.substring(dn.indexOf(',') + 1);

		return parent;
	}

	private static String getFilter(String dn) {
		String parent = dn.substring(0, dn.indexOf(','));

		return parent;
	}

	@Override
	public void acknowledgeCompletedOps(LinkedList<SyncOperation> completedOps) throws EndpointException {
	}

}
