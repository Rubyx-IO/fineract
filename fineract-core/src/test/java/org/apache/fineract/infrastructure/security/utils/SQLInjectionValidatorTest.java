/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.fineract.infrastructure.security.utils;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SQLInjectionValidatorTest {

    @Test
    void acceptsCompoundFiltersUsedByDownstreamServices() {
        assertDoesNotThrow(() -> SQLInjectionValidator
                .validateSQLInput("l.external_id is not null and (l.loan_status_id = 200 or l.loan_status_id = 100)"));
        assertDoesNotThrow(() -> SQLInjectionValidator
                .validateSQLInput("l.loan_status_id != 100 and l.loan_status_id != 200 and c.external_id = 'abc'"));
        assertDoesNotThrow(() -> SQLInjectionValidator.validateSQLInput("lsa.id = 42"));
        assertDoesNotThrow(() -> SQLInjectionValidator.validateSQLInput("c.id=1"));
        assertDoesNotThrow(() -> SQLInjectionValidator.validateSQLInput("c.display_name = 'Acme (Ltd)'"));
        assertDoesNotThrow(() -> SQLInjectionValidator.validateSQLInput("(c.id = 1 or c.id = 2) and c.status = 300"));
    }

    @Test
    void acceptsQuotedValuesWithKeywordsAndNonAsciiCharacters() {
        assertDoesNotThrow(() -> SQLInjectionValidator.validateSQLInput("c.display_name ilike '%Callum%' or c.account_no like 'Callum%'"));
        assertDoesNotThrow(() -> SQLInjectionValidator.validateSQLInput("c.display_name like '%José%'"));
        assertDoesNotThrow(() -> SQLInjectionValidator.validateSQLInput("c.display_name = 'O''Brien (Ltd)'"));
    }

    @Test
    void rejectsParenthesesThatCloseTheWrapper() {
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("c.id=1) or (c.id is not null"));
        assertThrows(SQLInjectionException.class,
                () -> SQLInjectionValidator.validateSQLInput("c.display_name = '(') or c.id > 0 or (c.display_name = ')'"));
        assertThrows(SQLInjectionException.class,
                () -> SQLInjectionValidator.validateSQLInput("c.display_name = \"(\") or c.id > 0 or (c.display_name = \")\""));
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("(c.id = 1"));
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("c.id = 1)"));
    }

    @Test
    void rejectsUnterminatedQuotesAndPlaceholders() {
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("c.display_name = 'abc"));
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("c.id = ?"));
    }

    @Test
    void rejectsCommandsCommentsAndEqualityTricks() {
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("c.id = 1 -- comment"));
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("c.id = 1 /* comment */"));
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("c.id = 1; drop table m_client"));
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("c.id = c.id"));
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("call some procedure"));
        assertThrows(SQLInjectionException.class, () -> SQLInjectionValidator.validateSQLInput("select * from m_client"));
    }
}
