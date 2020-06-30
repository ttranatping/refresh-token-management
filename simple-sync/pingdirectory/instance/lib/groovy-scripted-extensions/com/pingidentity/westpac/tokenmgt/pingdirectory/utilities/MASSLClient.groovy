package com.pingidentity.westpac.tokenmgt.pingdirectory.utilities;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;

public class MASSLClient {

	private final static Log LOGGER = LogFactory.getLog(MASSLClient.class);

	private final static String[] DEFAULT_HTTPSPROTOCOLS = { "TLSv1.1", "TLSv1.2" };
	private final static HostnameVerifier DEFAULT_HOSTNAMEVERIFIER = SSLConnectionSocketFactory
			.getDefaultHostnameVerifier();

	private static Map<String, KeyStore> keyStoreCache = new HashMap<String, KeyStore>();

	public static void removeKeystoreCacheItem(String keystoreIdentifier) {
		if (keyStoreCache.containsKey(keystoreIdentifier))
			keyStoreCache.remove(keystoreIdentifier);
	}

	public static HttpResponseObj executeGETHTTP(String url, Map<String, String> headers, String[] httpsProtocolSupport,
			String keystoreLocation, String rootCALocation, String keystorePassword, String keystoreType, boolean ignoreSSLErrors,
			int requestTimeout) throws Exception {

		return executeHTTP(url, "GET", headers, new StringEntity(""), httpsProtocolSupport, keystoreLocation, rootCALocation,
				keystorePassword, keystoreType, ignoreSSLErrors, requestTimeout);
	}

	public static HttpResponseObj executeHTTP(String url, String method, Map<String, String> headers, String data,
			String[] httpsProtocolSupport, String keystoreLocation, String rootCALocation, String keystorePassword, String keystoreType,
			boolean ignoreSSLErrors, int requestTimeout) throws Exception {

		StringEntity entity = new StringEntity(data);

		return executeHTTP(url, method, headers, entity, httpsProtocolSupport, keystoreLocation, keystoreType, rootCALocation, keystorePassword, ignoreSSLErrors,
				requestTimeout);
	}

	public static HttpResponseObj executeHTTP(String url, String method, Map<String, String> headers,
			Map<String, String> params, String[] httpsProtocolSupport, String keystoreLocation, String rootCALocation,
			String keystorePassword, String keystoreType, boolean ignoreSSLErrors, int requestTimeout) throws Exception {

		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		if (params != null) {
			for (String paramName : params.keySet()) {
				if (LOGGER.isTraceEnabled())
					LOGGER.trace(String.format("Adding http post params: %s=%s", paramName, params.get(paramName)));

				urlParameters.add(new BasicNameValuePair(paramName, params.get(paramName)));
			}
		}

		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(urlParameters);

		return executeHTTP(url, method, headers, entity, httpsProtocolSupport, keystoreLocation, keystoreType, rootCALocation, keystorePassword, ignoreSSLErrors,
				requestTimeout);
	}

	public static HttpResponseObj executeHTTP(String url, String method, Map<String, String> headers,
			StringEntity stringEntity, String[] httpsProtocolSupport, String keystoreLocation, String keystoreType, String rootCALocation,
			String keystorePassword, boolean ignoreSSLErrors, int requestTimeout) throws Exception {

		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace(String.format("Executing HTTP request with url: %s, method: %s, isIgnoreSSL: %s", url, method,
					String.valueOf(ignoreSSLErrors)));
		}

		if (httpsProtocolSupport == null || httpsProtocolSupport.length == 0)
			httpsProtocolSupport = DEFAULT_HTTPSPROTOCOLS;

		HostnameVerifier hostnameVerifier = DEFAULT_HOSTNAMEVERIFIER;

		SSLContextBuilder sslCtx = SSLContexts.custom();

		if (keystoreLocation != null) {
			String[] certFiles = new String[] { rootCALocation };

			KeyStore keystore = KeyStoreCreator.getKeyStore(keystorePassword, keystoreLocation, certFiles, keystoreType);

			if (LOGGER.isTraceEnabled())
				LOGGER.trace("Attempting to load private credentials");

			if (keystore == null) {
				if (LOGGER.isTraceEnabled())
					LOGGER.trace(
							String.format("New private key found, creating alias '%s' and caching private credentials",
									keystoreLocation));

				keyStoreCache.put(keystoreLocation, keystore);
			} else {
				if (LOGGER.isTraceEnabled())
					LOGGER.trace(String.format("Found keystore in cache for alias '%s'", keystoreLocation));
			}

			sslCtx.loadKeyMaterial(keystore, keystorePassword.toCharArray());
		}

		//TODO: reintroduce this
		if (ignoreSSLErrors) {
			hostnameVerifier = new NoopHostnameVerifier();
			sslCtx.loadTrustMaterial( 
				    null, 
				    new TrustStrategy ()
				    {

						@Override
						public boolean isTrusted(java.security.cert.X509Certificate[] arg0, String arg1)
								throws java.security.cert.CertificateException {
							// TODO Auto-generated method stub
							return true;
						}
				    });
		}

		SSLContext sslCtxBuild = sslCtx.build();

		SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslCtxBuild, httpsProtocolSupport,
				null, hostnameVerifier);

		HttpClient client = HttpClients.custom().setSSLSocketFactory(socketFactory).build();

		RequestConfig requestCfg = RequestConfig.custom().setConnectTimeout(requestTimeout)
				.setSocketTimeout(requestTimeout).build();

		HttpRequestBase request = null;
		switch (method.toUpperCase()) {
		case "POST":
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Initiating post request");

			HttpPost post = new HttpPost(url);

			post.setEntity(stringEntity);

			request = post;

			break;
		case "PUT":
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Initiating put request");

			HttpPut put = new HttpPut(url);

			put.setEntity(stringEntity);

			request = put;

			break;
		case "DELETE":
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Initiating delete request");
			
			HttpDelete delete = new HttpDelete(url);
			
			request = delete;
			break;
		default:
			HttpGet getreq = new HttpGet(url);
			request = getreq;

		}

		if (headers != null) {
			// add request header
			for (String headerName : headers.keySet()) {
				if (LOGGER.isTraceEnabled())
					LOGGER.trace(String.format("Adding http header: %s=%s", headerName, headers.get(headerName)));

				request.addHeader(headerName, headers.get(headerName));
			}
		}

		request.setConfig(requestCfg);

		HttpResponse response = client.execute(request);

		if (response == null) {
			if (LOGGER.isTraceEnabled())
				LOGGER.trace("Response is null for the request");

			return null;
		}

		if(method.equalsIgnoreCase("delete"))
			return new HttpResponseObj(response.getStatusLine().getStatusCode(), null);
		
		BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

		StringBuffer result = new StringBuffer();
		String line = "";
		while ((line = rd.readLine()) != null) {
			result.append(line);
		}

		if (LOGGER.isTraceEnabled())
			LOGGER.trace("Response is: " + result.toString());

		return new HttpResponseObj(response.getStatusLine().getStatusCode(), result.toString());

	}

}
