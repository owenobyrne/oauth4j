package org.oauth4j.core;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.oauth4j.util.OAuth4JConstants;
import org.oauth4j.util.OAuth4JException;
import org.oauth4j.util.OAuth4JUtil;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.oauth.client.OAuthClientFilter;
import com.sun.jersey.oauth.signature.HMAC_SHA1;
import com.sun.jersey.oauth.signature.OAuthParameters;
import com.sun.jersey.oauth.signature.OAuthSecrets;
import com.sun.jersey.oauth.signature.OAuthSignature;
import com.sun.jersey.oauth.signature.OAuthSignatureException;

public class OAuth4JService {
    private OAuth4JConsumer oAuth4JConsumer;
    private OAuth4JToken token;
    private OAuth4JToken accessToken;
    private OAuth4JServiceProvider oAuth4JServiceProvider;
    private Map<String, String> serviceParameters = new HashMap<String, String>();

    public OAuth4JService(OAuth4JConsumer oAuthConsumer,
	    Class<? extends OAuth4JServiceProvider> serviceProviderClazz,
	    String name) throws OAuth4JException {
	this.oAuth4JConsumer = oAuthConsumer;
	this.oAuth4JServiceProvider = OAuth4JUtil
	        .createInstance(serviceProviderClazz);
	this.serviceParameters.put(OAuth4JConstants.CLIENT_API_ID,
	        oAuth4JConsumer.getClientId());
	this.serviceParameters.put(OAuth4JConstants.CLIENT_API_KEY,
	        oAuth4JConsumer.getKey());
	this.serviceParameters.put(OAuth4JConstants.CONSUMER_SECRET,
	        oAuth4JConsumer.getSecret());
    }

    public OAuth4JService(String consumerKey, String consumerSecret,
	    Class<? extends OAuth4JServiceProvider> serviceProviderClazz,
	    String name) throws OAuth4JException {
	this.oAuth4JConsumer = new OAuth4JConsumer(consumerKey, consumerSecret);
	this.oAuth4JServiceProvider = OAuth4JUtil
	        .createInstance(serviceProviderClazz);
	this.serviceParameters.put(OAuth4JConstants.CLIENT_API_ID,
	        oAuth4JConsumer.getClientId());
	this.serviceParameters.put(OAuth4JConstants.CLIENT_API_KEY,
	        oAuth4JConsumer.getKey());
	this.serviceParameters.put(OAuth4JConstants.CONSUMER_SECRET,
	        oAuth4JConsumer.getSecret());
    }

    public OAuth4JRequest createRequest(String url, String appendToURL,
	    String... urlTokenData) {
	return new OAuth4JRequest(this, url, appendToURL, urlTokenData);
    }

    public OAuth4JRequest createRequest(OAuth4JServiceProviderService service) {
	return new OAuth4JRequest(this, service);
    }

    public OAuth4JRequest createRequest(OAuth4JServiceProviderService service,
	    String appendToURL, String... urlTokenData) {
	return new OAuth4JRequest(this, service, appendToURL, urlTokenData);
    }

    public OAuth4JToken getRequestToken(String callback, String scope)
	    throws OAuth4JException {
	OAuth4JServiceProviderService requestEndpoint = oAuth4JServiceProvider
	        .getRequestTokenEndpoint();
	OAuth4JRequest request = createRequest(requestEndpoint, null);
	if (OAuth4JUtil.hasText(callback)) {
	    request.setCallbackURL(callback);
	}
	if (OAuth4JUtil.hasText(scope)) {
	    request.addURLParameter("scope", scope);
	}
	token = (OAuth4JToken) execute(request, Call.REQUEST_TOKEN,
	        ClientResponse.class);

	serviceParameters.put(OAuth4JConstants.TOKEN, token.getToken());
	return token;
    }

    public OAuth4JToken getRequestToken() throws OAuth4JException {
	return getRequestToken(null, null);
    }

    public OAuth4JToken fetchAccessToken(String callback)
	    throws OAuth4JException {
	OAuth4JServiceProviderService requestEndpoint = oAuth4JServiceProvider
	        .getAccessTokenEndpoint();
	OAuth4JRequest request = createRequest(requestEndpoint, null);
	if (OAuth4JUtil.hasText(callback)) {
	    request.setCallbackURL(callback);
	}
	accessToken = (OAuth4JToken) execute(request, Call.ACCESS_TOKEN,
	        ClientResponse.class);
	serviceParameters.put(OAuth4JConstants.ACCESS_TOKEN,
	        accessToken.getToken());
	return accessToken;
    }

    public OAuth4JToken fetchAccessToken() throws OAuth4JException {
	return fetchAccessToken(null);
    }

    public OAuth4JToken getAccessToken() throws OAuth4JException {
	return accessToken;
    }

    public String getAuthenticationURL(String callback) throws OAuth4JException {
	if (token == null) {
	    token = getRequestToken(callback, null);
	}

	return getCallableAuthUrl();
    }

    public String getAuthenticationURL() throws OAuth4JException {
	if (token == null) {
	    token = getRequestToken();
	}

	return getCallableAuthUrl();
    }

    private String getCallableAuthUrl() {
	String url = null;
	String oauth_token = "";
	if (token != null) {
	    url = token.getAuthUrl() != null ? token.getAuthUrl()
		    : oAuth4JServiceProvider.getAuthorizeTokenEndpoint()
		            .getURL();
	    oauth_token = token.getToken();
	} else {
	    url = oAuth4JServiceProvider.getAuthorizeTokenEndpoint().getURL();
	}
	url = OAuth4JUtil.replaceTokens(url, serviceParameters);
	if (OAuth4JUtil.hasText(url)) {
	    if (url.contains(OAuth4JConstants.TOKEN)) {
		return url;
	    } else {
		return url + ((url.contains("?")) ? "&" : "?")
		        + OAuth4JConstants.TOKEN + "=" + oauth_token;
	    }
	} else {
	    return null;
	}
    }

    private <T> Object execute(OAuth4JRequest oAuth4JRequest, Call call,
	    Class<T> t) throws OAuth4JException {

	OAuthParameters params = new OAuthParameters()
	        .signatureMethod(HMAC_SHA1.NAME).timestamp().nonce().version();
	params.consumerKey(oAuth4JConsumer.getKey());

	OAuthSecrets secrets = new OAuthSecrets();
	secrets.consumerSecret(oAuth4JConsumer.getSecret());
    System.out.println("oauth4j consumer secret " + oAuth4JConsumer.getSecret());

	if (OAuth4JUtil.hasText(oAuth4JRequest.getCallbackURL())) {
	    params.callback(oAuth4JRequest.getCallbackURL());
	} else {
	    // params.callback(OAuth4JConstants.OUT_OF_BAND);
	}

	// establish the secrets that will be used to sign the request
	String endpoint = null;
	switch (call) {
	case REQUEST_TOKEN:
	    endpoint = oAuth4JRequest.getServiceProvider()
		    .getRequestTokenEndpoint().getURL();
	    break;
	case ACCESS_TOKEN:
	    endpoint = oAuth4JRequest.getServiceProvider()
		    .getAccessTokenEndpoint().getURL();
	    params.token(token.getToken()).verifier(token.getVerifier());
	    System.out.println("oauth4j token secret " + token.getTokenSecret());
	    secrets.tokenSecret(token.getTokenSecret());
	    params.realm(token.getRealm());
	    break;
	case PROCESS:
	    endpoint = oAuth4JRequest.getUrl();
	    params.token(accessToken.getToken());
	    secrets.tokenSecret(accessToken.getTokenSecret());
	    break;
	}

	String appendable = oAuth4JRequest.getAppendToURL();
	if (OAuth4JUtil.hasText(appendable)) {
	    if (appendable.indexOf(":") == 0) {
		endpoint += appendable;
	    } else {
		endpoint = (endpoint.indexOf("?") > -1) ? endpoint
		        .charAt(endpoint.length() - 1) == '=' ? endpoint
		        + appendable : endpoint + "&" + appendable : endpoint
		        + "?" + appendable;
	    }
	}

	Map<String, String> paramz = new HashMap<String, String>();
	paramz.putAll(serviceParameters);
	paramz.putAll(oAuth4JRequest.getUrlTokenData());
	endpoint = OAuth4JUtil.replaceTokens(endpoint, paramz);

	if (!OAuth4JUtil.hasText(endpoint)) {
	    throw new OAuth4JException("No endpoint specified!!");
	}
	endpoint = encode(endpoint);
	System.out.println("Endpoint resolved to -> " + endpoint);
	oAuth4JRequest.setUrl(endpoint);

	// generate the digital signature and set in the request
	try {
	    OAuthSignature.sign(oAuth4JRequest, params, secrets);
	} catch (OAuthSignatureException e) {
	    throw new OAuth4JException(e.getMessage());
	}

	Client client = Client.create();
	client.setFollowRedirects(true);
	OAuthClientFilter filter = new OAuthClientFilter(client.getProviders(),
	        params, secrets);
	// OAuth test server resource
	WebResource resource = client.resource(endpoint);

	resource.addFilter(filter);
	System.out.println(oAuth4JRequest.getHeaderParameters());
	// make the request (signing it in the process)
	T response = null;

	switch (oAuth4JRequest.getMethod()) {
	case GET:
	    response = resource.get(t);
	    break;
	case POST:
	    response = resource.post(t);
	    break;
	case PUT:
	    response = resource.put(t);
	    break;
	case DELETE:
	    response = resource.delete(t);
	    break;
	case OPTIONS:
	    response = resource.options(t);
	    break;
	case HEAD:
	    response = (T) resource.head();
	    break;
	default:
	    response = resource.post(t);
	    break;
	}

	if (call == Call.REQUEST_TOKEN || call == Call.ACCESS_TOKEN) {
	    ClientResponse clientResponse = (ClientResponse) response;
	    String entity = clientResponse.getEntity(String.class);
	    System.out.println("HEAD-> " + clientResponse.getHeaders());
	    System.out.println("PROP-> " + clientResponse.getProperties());
	    System.out.println("STATUS-> " + clientResponse.getStatus());
	    return OAuth4JToken.parse(call, entity);
	} else {
	    return response;
	}
    }

    private String encode(String endpoint) {
	if (endpoint.indexOf("?") == -1
	        || endpoint.length() == endpoint.indexOf("?") + 1) {
	    return endpoint;
	}

	String url = endpoint.substring(0, endpoint.indexOf("?") + 1);
	String query = endpoint.substring(endpoint.indexOf("?") + 1);

	String[] info = null;

	if (query.contains(OAuth4JConstants.PARAMETER_DELIMITER)) {
	    info = OAuth4JUtil.stringSplitter(query,
		    OAuth4JConstants.PARAMETER_DELIMITER);
	} else {
	    info = new String[] { query };
	}

	Map<String, String> param = new HashMap<String, String>();

	for (String string2 : info) {
	    String[] keyVal = OAuth4JUtil.stringSplitter(string2,
		    OAuth4JConstants.KEY_VAL_DELIMITER);
	    if (keyVal.length == 1)
		param.put(keyVal[0], "");
	    if (keyVal.length == 2)
		param.put(keyVal[0], keyVal[1]);
	}

	for (String key : param.keySet()) {
	    url += key + "=" + URLEncoder.encode(param.get(key)) + "&";
	}
	return url;
    }

    public ClientResponse process(OAuth4JRequest oAuth4JRequest)
	    throws OAuth4JException {
	if (accessToken == null) {
	    fetchAccessToken();
	}
	ClientResponse clientResponse = (ClientResponse) execute(
	        oAuth4JRequest, Call.PROCESS, ClientResponse.class);
	System.out.println("HEAD-> " + clientResponse.getHeaders());
	Client client = (Client) clientResponse.getProperties().get(
	        Client.class.getName());
	System.out.println("PROP-> " + client.getProperties());
	System.out.println("STATUS-> " + clientResponse.getStatus());
	return clientResponse;
    }

    public <T> T process(OAuth4JRequest oAuth4JRequest, Class<T> t)
	    throws OAuth4JException {
	return (T) execute(oAuth4JRequest, Call.PROCESS, t);
    }

    public OAuth4JConsumer getOAuth4JConsumer() {
	return oAuth4JConsumer;
    }

    public OAuth4JToken getToken() {
	return token;
    }

    public void setVerifier(String verifier) {
	this.serviceParameters.put(OAuth4JConstants.VERIFIER, verifier);
	token.setVerifier(verifier);
    }

    public void setAccessToken(OAuth4JToken accessToken) {
	this.accessToken = accessToken;
    }

    public OAuth4JServiceProvider getOAuth4JServiceProvider() {
	return oAuth4JServiceProvider;
    }

    public Map<String, String> getParameters() {
	return serviceParameters;
    }

    public Map<String, String> addParameter(String key, String value) {
	serviceParameters.put(key, value);
	return serviceParameters;
    }

    public void setToken(OAuth4JToken oAuth4JToken) {
	this.token = oAuth4JToken;
    }

    public enum Method {
	HEAD("HEAD"), OPTIONS("OPTIONS"), GET("GET"), PUT("PUT"), POST("POST"), DELETE(
	        "DELETE");
	private String text;

	private Method(String text) {
	    this.text = text;
	}

	public String getText() {
	    return text;
	}
    }

    public enum Protocol {
	HTTP("http"), HTTPS("https");
	private String text;

	private Protocol(String text) {
	    this.text = text;
	}

	public String getText() {
	    return text;
	}
    }

    public enum Call {
	REQUEST_TOKEN, ACCESS_TOKEN, PROCESS
    }

}
