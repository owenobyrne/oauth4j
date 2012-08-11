package org.oauth4j.core;

import org.oauth4j.core.OAuth4JService.Method;
import org.oauth4j.core.OAuth4JService.Protocol;

public interface OAuth4JServiceProviderService {
    public Method getMethod();

    public String getURL();

    public Protocol getProtocol();

    public <T> Class<T> getEntity();

    /**
     * Basically the number of non static parameters to be passed in the url 
     * 
     * @return param count
     */
    public int getURLParamCount();
}
