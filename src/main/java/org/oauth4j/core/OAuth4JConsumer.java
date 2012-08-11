package org.oauth4j.core;

/**
 * Contains the basic info of the consumer
 * 
 * @author jasphior
 * 
 */
public class OAuth4JConsumer {
    private String clientId;
    private String key;
    private String secret;

    public OAuth4JConsumer(String clientId, String key, String secret) {
	this.clientId = clientId;
	this.key = key;
	this.secret = secret;
    }

    public OAuth4JConsumer(String key, String secret) {
	this.key = key;
	this.secret = secret;
    }

    public String getClientId() {
	return clientId;
    }

    public String getKey() {
	return key;
    }

    public String getSecret() {
	return secret;
    }

}
