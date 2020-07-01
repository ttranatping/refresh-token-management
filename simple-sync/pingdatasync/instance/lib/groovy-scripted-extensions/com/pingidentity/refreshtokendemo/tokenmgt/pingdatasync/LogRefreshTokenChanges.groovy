package com.pingidentity.refreshtokendemo.tokenmgt.pingdatasync;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import com.unboundid.directory.sdk.common.types.LogSeverity;
import com.unboundid.directory.sdk.sync.config.SyncDestinationConfig;
import com.unboundid.directory.sdk.sync.scripting.ScriptedSyncDestination;
import com.unboundid.directory.sdk.sync.types.EndpointException;
import com.unboundid.directory.sdk.sync.types.SyncOperation;
import com.unboundid.directory.sdk.sync.types.SyncServerContext;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;

public class LogRefreshTokenChanges extends ScriptedSyncDestination {

	private static final String CONFIG_LOG_FILE_PATH = "log-file-path";
	private Logger logger = null;
	private SyncServerContext serverContext;

	private DateTimeFormatter formatter = null;

	@Override
	public void defineConfigArguments(ArgumentParser parser) {
		try {
			// yup some weird stuff to make groovy work
			char f = 'f';
			parser.addArgument(new StringArgument(f, CONFIG_LOG_FILE_PATH, true, 1, "", "Log file path."));

		} catch (ArgumentException e) {
			serverContext.logMessage(LogSeverity.SEVERE_ERROR,
					"LogRefreshTokenChanges: Error setting config arguments");
		}
	}

	@Override
	public void initializeSyncDestination(SyncServerContext serverContext, SyncDestinationConfig config,
			com.unboundid.util.args.ArgumentParser parser) throws EndpointException {
		super.initializeSyncDestination(serverContext, config, parser);
		this.serverContext = serverContext;

		String logFilePath = parser.getStringArgument(CONFIG_LOG_FILE_PATH).getValue();

		logger = createLogInstance("ConsentLogger", logFilePath);
		logger.setLevel(Level.ALL);

		formatter = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT).withLocale(Locale.UK)
				.withZone(ZoneId.systemDefault());

	}

	@Override
	public String getCurrentEndpointURL() {
		return "Sync:LogRefreshTokenChanges";

	}

	@Override
	public List<Entry> fetchEntry(Entry destEntryMappedFromSrc, SyncOperation operation) {

		Entry returnEntry = new Entry(destEntryMappedFromSrc.getDN());
		returnEntry.addAttribute("tokenMgtExpiringToken", "true");
		
		String accessToken = destEntryMappedFromSrc.getAttributeValue("tokenMgtAccessTokenJWT");
		
		if(accessToken != null)
			returnEntry.addAttribute("tokenMgtAccessTokenJWT",
					accessToken);

		
		String tokenMgtLastStatusError = destEntryMappedFromSrc.getAttributeValue("tokenMgtLastStatusError");
		if(tokenMgtLastStatusError != null)
			returnEntry.addAttribute("tokenMgtLastStatusError",
				destEntryMappedFromSrc.getAttributeValue("tokenMgtLastStatusError"));
		
		returnEntry.addAttribute("objectClass", "tokenMgt");

		List<Entry> returnList = new ArrayList<Entry>();
		returnList.add(returnEntry);

		return returnList;
	}

	@Override
	public void createEntry(Entry entryToCreate, SyncOperation operation) throws EndpointException {

		logItem(entryToCreate);
	}

	@Override
	public void modifyEntry(Entry entryToModify, List<Modification> modsToApply, SyncOperation operation)
			throws EndpointException {

		logItem(entryToModify);

	}

	private void logItem(Entry entry) {

		Instant instant = Instant.now();
		logger.log(Level.INFO, String.format("%s,%s,%s,%s", formatter.format(instant), entry.getDN(),
				entry.getAttributeValue("tokenMgtLastStatusError"), entry.getAttributeValue("tokenMgtAccessTokenJWT")));
	}

	@Override
	public void deleteEntry(Entry entryToDelete, SyncOperation operation) throws EndpointException {
	}

	public static Logger createLogInstance(String packaging, String logFileName) {
		Logger logger = Logger.getLogger(packaging);
		FileHandler fh;

		try {

			// This block configure the logger with handler and formatter
			fh = new FileHandler(logFileName);
			logger.addHandler(fh);
			SimpleFormatter formatter = new SimpleFormatter();
			fh.setFormatter(formatter);

		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return logger;

	}

}

