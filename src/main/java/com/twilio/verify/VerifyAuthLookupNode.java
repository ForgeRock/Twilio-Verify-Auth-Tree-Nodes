/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package com.twilio.verify;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;
import com.twilio.Twilio;
import com.twilio.rest.lookups.v1.PhoneNumber;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;

/**
 * Twilio Verify Collector Decision Node
 */
@Node.Metadata(outcomeProvider = VerifyAuthLookupNode.OutcomeProvider.class,
        configClass = VerifyAuthLookupNode.Config.class, tags = {"multi-factor authentication", "marketplace", "trustnetwork"})
public class VerifyAuthLookupNode extends AbstractDecisionNode {
    private final Logger logger = LoggerFactory.getLogger(VerifyAuthLookupNode.class);
    private final Config config;
    private String loggerPrefix = "[Twilio Lookup Node][Partner] ";


    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default String accountSID() {
            return "";
        }

        /**
         * The authentication token found in the Twilio account dashboard.
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        @Password
        char[] authToken();

        @Attribute(order = 300)
        default String identifierSharedState() {
            return "userIdentifier";
        }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public VerifyAuthLookupNode(@Assisted Config config) {
        this.config = config;
        Twilio.init(config.accountSID(), String.valueOf(config.authToken()));
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug(loggerPrefix + "Started");
        try {
            logger.debug(loggerPrefix + "Grabbing phone number from "+ config.identifierSharedState() +" shared state");
            String phoneNumber = context.sharedState.get(config.identifierSharedState()).asString();
            if(phoneNumber == null || phoneNumber == "") {
                logger.error(loggerPrefix + "Phone number not found");
                return Action.goTo("False").build();
            }
            logger.debug(loggerPrefix + "User phone number" + phoneNumber);
            PhoneNumber number = PhoneNumber
                    .fetcher(new com.twilio.type.PhoneNumber(phoneNumber))
                    .setType("carrier")
                    .fetch();

             String type = number.getCarrier().get("type");
             if (type.equals("mobile")) {
                logger.debug(loggerPrefix + "Phone type is mobile");
                return Action.goTo("True").build();

             }
             logger.error(loggerPrefix + "Phone type is not mobile");
             logger.error(loggerPrefix + "Phone type is " + type);
             return Action.goTo("False").build();
        } catch(Exception ex) {
            logger.error(loggerPrefix + "Exception occurred" + ex.getMessage());
            ex.printStackTrace();
            context.sharedState.put("Exception", ex.toString());
            return Action.goTo("Error").build();
        }

    }

    public static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
            /**
             * Outcomes Ids for this node.
             */
            static final String SUCCESS_OUTCOME = "True";
            static final String ERROR_OUTCOME = "Error";
            static final String NOT_FOUND_OUTCOME = "False";
           // static final String NOT_MOBILE_OUTCOME = "Not Mobile";
            private static final String BUNDLE = VerifyAuthLookupNode.class.getName();

            @Override
            public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

                ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

                List<Outcome> results = new ArrayList<>(
                        Arrays.asList(
                                new Outcome(SUCCESS_OUTCOME, SUCCESS_OUTCOME)
                        )
                );
                results.add(new Outcome(NOT_FOUND_OUTCOME, NOT_FOUND_OUTCOME));
                //results.add(new Outcome(NOT_MOBILE_OUTCOME, NOT_MOBILE_OUTCOME));
                results.add(new Outcome(ERROR_OUTCOME, ERROR_OUTCOME));

                return Collections.unmodifiableList(results);
            }
        }


}
