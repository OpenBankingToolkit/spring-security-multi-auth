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


import com.nimbusds.jwt.JWTParser;
import com.forgerock.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import com.forgerock.spring.security.multiauth.model.granttypes.CustomGrantType;
import com.forgerock.spring.security.multiauth.model.granttypes.ScopeGrantType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.BadCredentialsException;
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
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class StatelessAccessTokenCollectorTest {

    private StatelessAccessTokenCollector statelessAccessTokenCollector;

    @Before
    public void setUp() {
        this.statelessAccessTokenCollector = StatelessAccessTokenCollector.builder()
                .collectorName("stateless-access-token-for-test")
                .tokenValidator((token, currentAuthentication) -> JWTParser.parse(token))
                .build();
    }

    @Test
    public void testAuthorisation() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader("Authorization")).thenReturn(
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl0sImNuZiI6eyJ4NXQjUzI1NiI6IjUzNjlhYmUzYjEyMDI1Y2RkZDk4NDUwZTViZWYyNTUwYzAzNmNhNzkifX0.dfrByVbVWSKPi0_OQQowaV2M9k_miFhNWdAL_VrQpXs");

        //When
        Authentication authentication = statelessAccessTokenCollector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(CustomGrantType.INTERNAL)));

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(CustomGrantType.INTERNAL, new ScopeGrantType("accounts"), new ScopeGrantType("payments")).collect(Collectors.toSet()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test(expected = BadCredentialsException.class)
    public void testWrongAccessTokenFormat() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader("Authorization")).thenReturn(
                "Bearer wrwerwOUPPS");

        //When
        statelessAccessTokenCollector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(CustomGrantType.INTERNAL)));

        //Then BadCredentialsException
    }
}