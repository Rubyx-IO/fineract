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

import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;

public final class SQLInjectionValidator {

    private SQLInjectionValidator() {

    }

    private static final String[] DDL_COMMANDS = { "create", "drop", "alter", "truncate", "comment", "sleep" };

    private static final String[] DML_COMMANDS = { "select", "insert", "update", "delete", "merge", "upsert", "call" };

    private static final String[] COMMENTS = { "--", "({", "/*", "#" };

    private static final String SQL_PATTERN = "[a-zA-Z_=,\\-'!><.?\"`% ()0-9*\n\r]*";

    public static void validateSQLInput(final String sqlSearch) {
        if (StringUtils.isBlank(sqlSearch)) {
            return;
        }

        StringBuilder unquoted = new StringBuilder(sqlSearch.length());
        int depth = 0;
        char quote = 0;
        for (int i = 0; i < sqlSearch.length(); i++) {
            char c = sqlSearch.charAt(i);
            if (quote != 0) {
                if (c == quote) {
                    if (i + 1 < sqlSearch.length() && sqlSearch.charAt(i + 1) == quote) {
                        i++;
                    } else {
                        quote = 0;
                    }
                }
                unquoted.append(' ');
                continue;
            }
            if (c == '\'' || c == '"' || c == '`') {
                quote = c;
                unquoted.append('q');
                continue;
            }
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth < 0) {
                    throw new SQLInjectionException();
                }
            } else if (c == '?' || !isAllowedOutsideQuotes(c)) {
                throw new SQLInjectionException();
            }
            unquoted.append(Character.toLowerCase(c));
        }
        if (quote != 0 || depth != 0) {
            throw new SQLInjectionException();
        }

        String inputSqlString = unquoted.toString();
        for (String ddl : DDL_COMMANDS) {
            if (containsWord(inputSqlString, ddl)) {
                throw new SQLInjectionException();
            }
        }
        for (String dml : DML_COMMANDS) {
            if (containsWord(inputSqlString, dml)) {
                throw new SQLInjectionException();
            }
        }
        for (String comments : COMMENTS) {
            if (inputSqlString.contains(comments)) {
                throw new SQLInjectionException();
            }
        }

        // Removing the space before and after '=' operator
        // String s = " \" OR 1 = 1"; For the cases like this
        while (inputSqlString.indexOf(" =") > 0) {
            inputSqlString = inputSqlString.replaceAll(" =", "=");
        }

        while (inputSqlString.indexOf("= ") > 0) {
            inputSqlString = inputSqlString.replaceAll("= ", "=");
        }

        StringTokenizer tokenizer = new StringTokenizer(inputSqlString, " ");
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken().trim();
            int equals = token.indexOf('=');
            if (equals > 0) {
                char before = token.charAt(equals - 1);
                if (before == '!' || before == '<' || before == '>') {
                    continue;
                }
                String operand = token.substring(0, equals).trim();
                String value = token.substring(equals + 1).trim();
                if (value.isEmpty() || operand.equals(value)) {
                    throw new SQLInjectionException();
                }
            }
        }
    }

    private static boolean isAllowedOutsideQuotes(final char c) {
        boolean asciiLetterOrDigit = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        return asciiLetterOrDigit || c == '_' || c == '=' || c == ',' || c == '-' || c == '!' || c == '>' || c == '<' || c == '.'
                || c == '%' || c == '*' || c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '(' || c == ')';
    }

    private static boolean containsWord(final String text, final String word) {
        int index = text.indexOf(word);
        while (index >= 0) {
            boolean startOk = index == 0 || !isWordChar(text.charAt(index - 1));
            int end = index + word.length();
            boolean endOk = end >= text.length() || !isWordChar(text.charAt(end));
            if (startOk && endOk) {
                return true;
            }
            index = text.indexOf(word, index + 1);
        }
        return false;
    }

    private static boolean isWordChar(final char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
    }

    public static void validateAdhocQuery(final String sqlSearch) {
        if (StringUtils.isBlank(sqlSearch)) {
            return;
        }
        String lowerCaseSQL = sqlSearch.toLowerCase().trim();
        for (String ddl : DDL_COMMANDS) {
            if (lowerCaseSQL.startsWith(ddl)) {
                throw new SQLInjectionException();
            }
        }

        for (String comments : COMMENTS) {
            if (lowerCaseSQL.contains(comments)) {
                throw new SQLInjectionException();
            }
        }

        // Removing the space before and after '=' operator
        // String s = " \" OR 1 = 1"; For the cases like this
        boolean injectionFound = false;
        String inputSqlString = lowerCaseSQL;
        while (inputSqlString.indexOf(" =") > 0) { // Don't remove space before
                                                   // = operator
            inputSqlString = inputSqlString.replaceAll(" =", "=");
        }

        while (inputSqlString.indexOf("= ") > 0) { // Don't remove space after =
                                                   // operator
            inputSqlString = inputSqlString.replaceAll("= ", "=");
        }

        StringTokenizer tokenizer = new StringTokenizer(inputSqlString, " ");
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken().trim();
            if (token.equals("'")) {
                if (tokenizer.hasMoreElements()) {
                    String nextToken = tokenizer.nextToken().trim();
                    if (!nextToken.equals("'")) {
                        injectionFound = true;
                        break;
                    }
                } else {
                    injectionFound = true;
                    break;
                }
            }
            if (token.equals("\"")) {
                if (tokenizer.hasMoreElements()) {
                    String nextToken = tokenizer.nextToken().trim();
                    if (!nextToken.equals("\"")) {
                        injectionFound = true;
                        break;
                    }
                } else {
                    injectionFound = true;
                    break;
                }
            } else if (token.indexOf('=') > 0) {
                StringTokenizer operatorToken = new StringTokenizer(token, "=");
                String operand = operatorToken.nextToken().trim();
                if (!operatorToken.hasMoreTokens()) {
                    injectionFound = true;
                    break;
                }
                String value = operatorToken.nextToken().trim();
                if (operand.equals(value)) {
                    injectionFound = true;
                    break;
                }
            }
        }
        if (injectionFound) {
            throw new SQLInjectionException();
        }

        Pattern pattern = Pattern.compile(SQL_PATTERN);
        Matcher matcher = pattern.matcher(sqlSearch);
        if (!matcher.matches()) {
            throw new SQLInjectionException();
        }
    }
}
