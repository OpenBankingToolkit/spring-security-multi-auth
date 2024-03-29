/**
 * Copyright 2019 Quentin Castel.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.forgerock.spring.security.multiauth.configurers.collectors;

import com.forgerock.spring.security.multiauth.configurers.AuthCollector;
import com.forgerock.spring.security.multiauth.model.authentication.AuthenticationWithEditableAuthorities;
import com.nimbusds.jose.JOSEException;
import com.forgerock.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import lombok.AllArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@ToString
@AllArgsConstructor
public abstract class CustomCookieCollector<T> implements AuthCollector {

    private String collectorName;
    protected TokenValidator<T> tokenValidator;
    protected UsernameCollector<T> usernameCollector;
    protected AuthoritiesCollector<T> authoritiesCollector;
    protected String cookieName;

    @Override
    public String collectorName() {
        return collectorName;
    }

    @Override
    public AuthenticationWithEditableAuthorities collectAuthentication(HttpServletRequest request) {
        log.trace("Looking for cookies");
        Cookie cookie = getCookie(request, cookieName);
        if (cookie != null) {
            String tokenSerialised = cookie.getValue();
            log.trace("Token received", tokenSerialised);
            try {
                T t = tokenValidator.validate(tokenSerialised);
                log.trace("Cookie valid");
                String userName = usernameCollector.getUserName(t);
                log.trace("Username {} found", userName);
                return createAuthenticationUser(userName, t);
            } catch (HttpClientErrorException e) {
                log.trace("Cookie not valid");
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                    throw new BadCredentialsException("Invalid cookie", e);
                }
                throw e;
            } catch (ParseException e) {
                log.trace("Cookie not valid", e);
                throw new BadCredentialsException("Invalid cookie", e);
            } catch (JOSEException e) {
                log.trace("Couldn't parse the cookie", e);
                throw new BadCredentialsException("Invalid cookie", e);
            }
        } else {
            log.trace("No cookie found");
        }
        return null;
    }

    @Override
    public AuthenticationWithEditableAuthorities collectAuthorisation(HttpServletRequest request, AuthenticationWithEditableAuthorities currentAuthentication) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        Cookie cookie = getCookie(request, cookieName);
        if (cookie != null) {
            String tokenSerialised = cookie.getValue();
            log.trace("Token received {} from cookie '{}'", tokenSerialised, cookieName);
            try {
                T t = tokenValidator.validate(tokenSerialised);
                Set<GrantedAuthority> authoritiesFound = authoritiesCollector.getAuthorities(t);
                log.trace("Authorities founds: {}", authorities);
                authorities.addAll(authoritiesFound);
            } catch (HttpClientErrorException e) {
                log.trace("Cookie not valid", e);
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                    throw new BadCredentialsException("Invalid cookie", e);
                }
                throw e;
            } catch (ParseException e) {
                log.trace("Couldn't parse cookie", e);
                throw new BadCredentialsException("Invalid cookie", e);
            } catch (JOSEException e) {
                log.trace("Couldn't parse the access token", e);
                throw new BadCredentialsException("Invalid access token", e);
            }
        } else {
            log.trace("No cookie found");
        }
        log.trace("Final authorities merged with previous authorities: {}", authorities);
        return currentAuthentication.addAuthorities(authorities);
    }

    protected AuthenticationWithEditableAuthorities createAuthenticationUser(String username, T token) {
        return new PasswordLessUserNameAuthentication(username, Collections.EMPTY_SET);
    }

    private Cookie getCookie(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(name)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    public interface TokenValidator<T> {
        T validate(String tokenSerialised) throws ParseException, JOSEException;
    }

    public interface UsernameCollector<T> {
        String getUserName(T token) throws ParseException;
    }

    public interface AuthoritiesCollector<T> {
        Set<GrantedAuthority> getAuthorities(T token) throws ParseException;
    }

    @Override
    public boolean isSetupForAuthentication() {
        return usernameCollector != null;
    }

    @Override
    public boolean isSetupForAuthorisation() {
        return authoritiesCollector != null;
    }
}
