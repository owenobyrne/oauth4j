package org.oauth4j.core;

import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

import org.oauth4j.core.OAuth4JService.Call;
import org.oauth4j.util.OAuth4JConstants;
import org.oauth4j.util.OAuth4JUtil;

import com.sun.jersey.api.uri.UriComponent;
import com.sun.jersey.oauth.signature.OAuthParameters;

public class OAuth4JToken {
    private Map<String, String> params = new HashMap<String, String>();

    private int type;

    public OAuth4JToken(int type) {
	this.type = type;
    }

    public OAuth4JToken(String key, String secret) {
	addParam(OAuthParameters.TOKEN, key);
	addParam(OAuthParameters.TOKEN_SECRET, secret);
    }

    public static OAuth4JToken parse(Call call, String string) {
	OAuth4JToken token = new OAuth4JToken(call.ordinal());
	String[] info = OAuth4JUtil.stringSplitter(string,
	        OAuth4JConstants.PARAMETER_DELIMITER);
	for (String string2 : info) {
	    String[] keyVal = OAuth4JUtil.stringSplitter(string2,
		    OAuth4JConstants.KEY_VAL_DELIMITER);
	    if (keyVal.length == 2)
		token.addParam(keyVal[0], UriComponent.decode(keyVal[1], UriComponent.Type.UNRESERVED));
	}
	return token;
    }

    public void setVerifier(String verifier) {
	if (OAuth4JUtil.hasText(verifier)) {
	    params.put(OAuthParameters.VERIFIER, verifier);
	}
    }

    public String getToken() {
	Object obj = null;
	if (type == 0) {
	    obj = params.get(OAuth4JConstants.TOKEN);
	} else {
	    obj = params.get(OAuth4JConstants.ACCESS_TOKEN);
	    // access_token can be null too... (depends on service provider) its
	    // ok... in that case we can continue with oauth_token
	    obj = (obj == null) ? params.get(OAuth4JConstants.TOKEN) : obj;
	}
	return obj != null ? String.valueOf(obj) : null;
    }

    public String getTokenSecret() {
	Object obj = params.get(OAuthParameters.TOKEN_SECRET);
	return obj != null ? String.valueOf(obj) : null;
    }

    public boolean getCallBackConfirmed() {
	Object obj = params.get(OAuthParameters.CALLBACK_CONFIRMED);
	return obj != null ? Boolean.parseBoolean(String.valueOf(obj)) : null;
    }

    public int getExpiry() {
	Object obj = params.get(OAuth4JConstants.OAUTH_AUTH_EXPIRY);
	return obj != null ? Integer.valueOf(String.valueOf(obj)) : null;
    }

    public String getAuthUrl() {
	Object obj = params.get(OAuth4JConstants.AUTH_URL);
	return obj != null ? URLDecoder.decode(String.valueOf(obj)) : null;
    }

    public String getRealm() {
	Object obj = params.get(OAuthParameters.REALM);
	return obj != null ? String.valueOf(obj) : null;
    }

    public String getVerifier() {
	Object obj = params.get(OAuthParameters.VERIFIER);
	return obj != null ? String.valueOf(obj) : null;
    }

    public void addParam(String key, String value) {
	params.put(key, value);
    }

    public String getParam(String key) {
	return params.get(key);
    }

    public Map<String, String> getParams() {
	return params;
    }

    public Map<String, String> getSessionParameters() {
	Map<String, String> sessionParams = new HashMap<String, String>();
	for (String prm : OAuth4JConstants.SESSION_PARAMS) {
	    if (params.containsKey(prm))
		sessionParams.put(prm, params.get(prm));
	}
	return sessionParams;
    }

    @Override
    public String toString() {
	StringBuilder builder = new StringBuilder();
	builder.append("OAuth4JToken [params=").append(params).append("]");
	return builder.toString();
    }

}