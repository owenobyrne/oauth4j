package org.oauth4j.core;

import org.oauth4j.core.OAuth4JService.Method;
import org.oauth4j.core.OAuth4JService.Protocol;

public class SimpleOAuth4JSPService implements OAuth4JServiceProviderService {
    private Protocol protocol;
    private Method method;
    private String url;
    private Class entity;
    private int urlParams;

    public SimpleOAuth4JSPService(final Protocol protocol, final Method method,
            final String url, final Class entity, final int urlParams) {
        this.protocol = protocol;
        this.method = method;
        this.url = url;
        this.entity = entity;
        this.urlParams = urlParams;
    }

    @Override
    public Method getMethod() {
        return method;
    }

    @Override
    public String getURL() {
        return url;
    }

    @Override
    public Protocol getProtocol() {
        return protocol;
    }

    @Override
    public <T> Class<T> getEntity() {
        return entity;
    }

    @Override
    public int getURLParamCount() {
        return urlParams;
    }

}
