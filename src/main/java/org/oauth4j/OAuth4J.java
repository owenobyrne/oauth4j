package org.oauth4j;

import org.oauth4j.core.OAuth4JConsumer;
import org.oauth4j.core.OAuth4JService;
import org.oauth4j.core.OAuth4JServiceProvider;
import org.oauth4j.util.OAuth4JException;

public class OAuth4J {

    private OAuth4J() {
    }

    public static OAuth4JService createOAuth4JService(
            OAuth4JConsumer oAuthConsumer,
            Class<? extends OAuth4JServiceProvider> serviceProviderClazz,
            String name) throws OAuth4JException {
        return new OAuth4JService(oAuthConsumer, serviceProviderClazz, name);
    }

    public static OAuth4JService createOAuth4JService(String consumerSecret,
            String consumerKey,
            Class<? extends OAuth4JServiceProvider> serviceProviderClazz,
            String name) throws OAuth4JException {
        return new OAuth4JService(consumerKey, consumerSecret,
                serviceProviderClazz, name);
    }
}
