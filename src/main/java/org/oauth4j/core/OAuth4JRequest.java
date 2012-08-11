package org.oauth4j.core;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.oauth4j.core.OAuth4JService.Method;
import org.oauth4j.core.OAuth4JService.Protocol;
import org.oauth4j.util.OAuth4JException;
import org.oauth4j.util.OAuth4JUtil;

import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.oauth.signature.OAuthParameters;
import com.sun.jersey.oauth.signature.OAuthRequest;

/**
 * Implementation of OAuthRequest
 * 
 * {@link OAuthRequest}
 * 
 * @author jasphior
 * 
 */
public class OAuth4JRequest implements OAuthRequest {

    private Map<String, List<String>> oauthParameters = new HashMap<String, List<String>>();
    private Map<String, List<String>> headerParameters = new HashMap<String, List<String>>();

    private Protocol protocol;
    private String serviceName;
    private String url;
    private Method method = Method.GET;
    private String contentType;
    private Class entity;
    private int portNumber;
    private OAuth4JService oAuth4JService;
    private OAuth4JServiceProvider serviceProvider;
    private OAuth4JServiceProviderService serviceProviderService;
    private String appendToURL;
    private Map<String, String> urlTokenData = new HashMap<String, String>();
    private String callbackURL;

    public OAuth4JRequest(OAuth4JService oAuth4JService, String url,
	    String appendToURL, String... urlTokenData) {
	this.oAuth4JService = oAuth4JService;
	this.serviceProvider = oAuth4JService.getOAuth4JServiceProvider();
	this.url = url;
	this.appendToURL = appendToURL;
	this.urlTokenData = OAuth4JUtil.convertToKeyValue(urlTokenData);
    }

    public OAuth4JRequest(OAuth4JService oAuth4JService,
	    OAuth4JServiceProviderService service, String appendToURL,
	    String... urlTokenData) {
	this.oAuth4JService = oAuth4JService;
	this.serviceProvider = oAuth4JService.getOAuth4JServiceProvider();
	this.serviceProviderService = service;
	this.url = service.getURL();
	this.protocol = service.getProtocol();
	this.method = service.getMethod();
	this.entity = service.getEntity();
	this.appendToURL = appendToURL;
	this.urlTokenData = OAuth4JUtil.convertToKeyValue(urlTokenData);
    }

    public OAuth4JRequest(OAuth4JService oAuth4JService,
	    OAuth4JServiceProviderService service) {
	this.oAuth4JService = oAuth4JService;
	this.serviceProvider = oAuth4JService.getOAuth4JServiceProvider();
	this.serviceProviderService = service;
	this.url = service.getURL();
	this.protocol = service.getProtocol();
	this.method = service.getMethod();
	this.entity = service.getEntity();
    }

    public ClientResponse process() throws OAuth4JException {
	return oAuth4JService.process(this);
    }

    @Override
    public void addHeaderValue(String key, String value)
	    throws IllegalStateException {
	List<String> values = headerParameters
	        .get(OAuthParameters.AUTHORIZATION_HEADER);
	String val;
	if (values != null && !values.isEmpty()) {
	    val = values.get(0);
	    if (OAuth4JUtil.hasText(val)) {
		if (val.contains(OAuthParameters.SCHEME)) {
		    val = val + ", " + key + "=" + value;
		} else {
		    val = value + ", " + val;
		}
	    }
	} else {
	    if (key.equals(OAuthParameters.AUTHORIZATION_HEADER)) {
		val = value;
	    } else {
		val = key + "=" + value;
	    }
	}
	values = new ArrayList<String>();
	values.add(val);
	headerParameters.put(OAuthParameters.AUTHORIZATION_HEADER, values);
    }

    public void addURLParameter(String key, String value)
	    throws IllegalStateException {
	String param = key + "=" + value;
	if (OAuth4JUtil.hasText(appendToURL)) {
	    appendToURL = appendToURL + "&" + param;
	} else {
	    appendToURL = param;
	}
    }

    public void addHeaderValues(Map<String, String> keyValues)
	    throws IllegalStateException {
	for (String key : keyValues.keySet()) {
	    addHeaderValue(key, keyValues.get(key));
	}
    }

    @Override
    public List<String> getHeaderValues(String key) {
	return headerParameters.get(key);
    }

    @Override
    public Set<String> getParameterNames() {
	return oauthParameters.keySet();
    }

    @Override
    public List<String> getParameterValues(String key) {
	return oauthParameters.get(key);
    }

    @Override
    public String getRequestMethod() {
	return method.getText();
    }

    @Override
    public URL getRequestURL() {
	try {
	    String reqURL = "";
	    if (OAuth4JUtil.hasText(url)) {
		reqURL = url;
	    } else if (serviceProviderService != null) {
		reqURL = serviceProviderService.getURL();
	    } else if (oAuth4JService != null) {
		reqURL = oAuth4JService.getOAuth4JServiceProvider()
		        .getRequestTokenEndpoint().getURL();
	    }
	    return new URL(reqURL);
	} catch (MalformedURLException e) {
	    System.out.println("ERROR: Invalid URL!");
	    e.printStackTrace();
	    return null;
	}
    }

    public void setUrl(String url) {
	this.url = url;
    }

    public Map<String, List<String>> getOauthParameters() {
	return oauthParameters;
    }

    public Map<String, List<String>> getHeaderParameters() {
	return headerParameters;
    }

    public Protocol getProtocol() {
	return protocol;
    }

    public String getServiceName() {
	return serviceName;
    }

    public String getUrl() {
	return url;
    }

    public String getAppendToURL() {
	return appendToURL;
    }

    public OAuth4JRequest appendToURL(String key, String value) {
	if (appendToURL == null) {
	    appendToURL = "";
	}
	appendToURL += "&" + key + "=" + value;
	return this;
    }

    public Method getMethod() {
	return method;
    }

    public String getContentType() {
	return contentType;
    }

    public Class getEntity() {
	return entity;
    }

    public int getPortNumber() {
	return portNumber;
    }

    public OAuth4JService getoAuth4JService() {
	return oAuth4JService;
    }

    public OAuth4JServiceProvider getServiceProvider() {
	return serviceProvider;
    }

    public OAuth4JServiceProviderService getServiceProviderService() {
	return serviceProviderService;
    }

    public Map<String, String> getUrlTokenData() {
	return urlTokenData;
    }

    public String getCallbackURL() {
	return callbackURL;
    }

    public void setCallbackURL(String callbackURL) {
	this.callbackURL = callbackURL;
    }

    @Override
    public String toString() {
	StringBuilder builder = new StringBuilder();
	builder.append("OAuth4JRequest [oauthParameters=")
	        .append(oauthParameters).append(", headerParameters=")
	        .append(headerParameters).append(", protocol=")
	        .append(protocol).append(", serviceName=").append(serviceName)
	        .append(", url=").append(url).append(", method=")
	        .append(method).append(", contentType=").append(contentType)
	        .append(", entity=").append(entity).append(", portNumber=")
	        .append(portNumber).append(", oAuth4JService=")
	        .append(oAuth4JService).append(", serviceProvider=")
	        .append(serviceProvider).append(", serviceProviderService=")
	        .append(serviceProviderService).append(", appendToURL=")
	        .append(appendToURL).append(", urlTokenData=")
	        .append(urlTokenData).append("]");
	return builder.toString();
    }

}
