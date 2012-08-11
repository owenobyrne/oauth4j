package org.oauth4j.core;


import org.oauth4j.jaxb.OAuth4JError;

import com.sun.jersey.api.client.ClientResponse;

public class OAuth4JResponse {
	private ClientResponse clientResponse;

	public OAuth4JResponse(ClientResponse clientResponse) {
		this.clientResponse = clientResponse;
	}

	public boolean hasError() {
		int statusCode = clientResponse.getStatus();
		switch (statusCode / 100) {

		case 1:
			// Family.INFORMATIONAL;
			return false;
		case 2:
			// Family.SUCCESSFUL;
			return false;
		case 3:
			// Family.REDIRECTION;
			return false;
		case 4:
			// Family.CLIENT_ERROR;
			return true;
		case 5:
			// Family.SERVER_ERROR;
			return true;
		default:
			// Family.OTHER;
			return false;
		}
	}

	public OAuth4JError getError() {
		return clientResponse.getEntity(OAuth4JError.class);
	}
}
