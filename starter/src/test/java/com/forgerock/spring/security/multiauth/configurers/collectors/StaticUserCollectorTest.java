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


import com.forgerock.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import com.forgerock.spring.security.multiauth.model.granttypes.CustomGrantType;
import com.forgerock.spring.security.multiauth.model.granttypes.ScopeGrantType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class StaticUserCollectorTest {

    private StaticUserCollector staticUserCollector;

    @Before
    public void setUp() {

        this.staticUserCollector = StaticUserCollector.builder()
                        .collectorName("statis-user-toto-for-test")
                        .usernameCollector(() -> "toto")
                        .grantedAuthorities(Stream.of(CustomGrantType.INTERNAL).collect(Collectors.toSet()))
                        .build();
    }

    @Test
    public void testAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        //When
        Authentication authentication = staticUserCollector.collectAuthentication(mockedRequest);

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Collections.emptySet())
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();
        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
    }

    @Test
    public void testAuthorisation() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));


        ScopeGrantType accountsScope = new ScopeGrantType("accounts");

        //When
        Authentication authentication = staticUserCollector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(accountsScope)));

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(CustomGrantType.INTERNAL, accountsScope).collect(Collectors.toSet()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }
}