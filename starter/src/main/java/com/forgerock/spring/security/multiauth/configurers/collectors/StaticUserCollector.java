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
import com.forgerock.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Builder
@AllArgsConstructor
public class StaticUserCollector implements AuthCollector {

    private UsernameCollector usernameCollector;
    private Set<GrantedAuthority> grantedAuthorities = Collections.EMPTY_SET;
    private String collectorName = this.getClass().getName();

    @Override
    public String collectorName() {
        return collectorName;
    }

    @Override
    public AuthenticationWithEditableAuthorities collectAuthentication(HttpServletRequest request) {
        return new PasswordLessUserNameAuthentication(usernameCollector.getUserName(), Collections.EMPTY_SET);
    }

    @Override
    public AuthenticationWithEditableAuthorities collectAuthorisation(HttpServletRequest request, AuthenticationWithEditableAuthorities currentAuthentication) {

        Set<GrantedAuthority> authorities = new HashSet<>(grantedAuthorities);
        log.trace("Authorities setup for the static user: {}", authorities);
        authorities.addAll(currentAuthentication.getAuthorities());
        log.trace("Final authorities merged with previous authorities: {}", authorities);

        return currentAuthentication.addAuthorities(authorities);
    }

    public interface UsernameCollector {
        String getUserName();
    }

    @Override
    public boolean isSetupForAuthentication() {
        return usernameCollector != null;
    }

    @Override
    public boolean isSetupForAuthorisation() {
        return true;
    }
}
