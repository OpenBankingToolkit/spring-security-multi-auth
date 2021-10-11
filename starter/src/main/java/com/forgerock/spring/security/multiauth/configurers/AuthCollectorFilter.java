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
package com.forgerock.spring.security.multiauth.configurers;

import com.forgerock.spring.security.multiauth.model.authentication.AuthenticationWithEditableAuthorities;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Slf4j
@Builder
@AllArgsConstructor
public class AuthCollectorFilter extends OncePerRequestFilter {

    private List<AuthCollector> authenticationCollectors;
    private List<AuthCollector> authorizationCollectors;

    private AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        try {
            log.info("doFilterInternal() called for request to {}", request.getRequestURI());
            AuthenticationWithEditableAuthorities currentAuthentication = null;
            for (AuthCollector authnCollector : authenticationCollectors) {
                log.debug("doFilterInternal() collecting from collector name: '{}'", authnCollector.collectorName());

                log.trace("doFilterInternal() Ensure collector is setup correctly to handle authentication");
                if (!authnCollector.isSetupForAuthentication()) {
                    log.warn("doFilterInternal() No username collector. Either setup a username " +
                            "collector or configure this collector '{}' to only handle authorization",
                            authnCollector.collectorName());
                    continue;
                }
                currentAuthentication = authnCollector.collectAuthentication(request);
                if (currentAuthentication != null) {
                    log.debug("doFilterInternal() Collector found an authentication {}, skip next collectors",
                            currentAuthentication);
                    break;
                } else {
                    log.debug("doFilterInternal() Collector didn't find an authentication, continuing with the next " +
                            "collector");
                }
            }

            if (currentAuthentication == null) {
                log.info("doFilterInternal() No authentication found by any of the collectors. Will not collect " +
                        "authorizations");
                chain.doFilter(request, response);
                return;
            }

            currentAuthentication.setAuthenticated(true);

            log.trace("doFilterInternal() Going through all the authorization collectors to authorize the request");
            for (AuthCollector authzCollector : authorizationCollectors) {
                log.trace("doFilterInternal() Ensure collector {} is setup correctly to handle authorisation",
                        authzCollector.collectorName());
                if (!authzCollector.isSetupForAuthorisation()) {
                    log.warn("doFilterInternal() No authorities collector. Either setup an " +
                            "authorities collector or configure this collector '" + authzCollector.collectorName() +
                            "' to only handle authentication");
                    continue;
                }
                currentAuthentication = authzCollector.collectAuthorisation(request, currentAuthentication);
            }
            if (currentAuthentication != null) {
                log.info("doFilterInternal() Authentications collected: {}", currentAuthentication);
                SecurityContextHolder.getContext().setAuthentication(currentAuthentication);
            } else {
                log.info("doFilterInternal() No authentications were collected from any of the collectors");
            }
            chain.doFilter(request, response);
        }  catch (AuthenticationException e) {
            log.info("doFilterInternal() An authentication failure exception happened!", e);
            authenticationFailureHandler.onAuthenticationFailure(request, response, e);
        }
    }
}
