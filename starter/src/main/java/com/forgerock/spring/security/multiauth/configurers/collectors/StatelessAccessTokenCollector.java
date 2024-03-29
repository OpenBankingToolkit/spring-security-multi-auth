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

import com.nimbusds.jwt.JWT;
import com.forgerock.spring.security.multiauth.model.granttypes.ScopeGrantType;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.stream.Collectors;

@Slf4j
@ToString
@Getter
public class StatelessAccessTokenCollector extends AccessTokenCollector<JWT> {

    @Builder
    public StatelessAccessTokenCollector(
            String collectorName,
            TokenValidator<JWT> tokenValidator
    ) {
        this.collectorName = collectorName;
        this.authoritiesCollector = token -> {
            if (token.getJWTClaimsSet().getStringListClaim("scope") == null) {
                log.trace("No claim 'scope' founds in the access token");
                return Collections.EMPTY_SET;
            }
            return token.getJWTClaimsSet().getStringListClaim("scope")
                    .stream()
                    .map(s -> new ScopeGrantType(s)).collect(Collectors.toSet());
        };
        this.tokenValidator = tokenValidator;
    }
}
