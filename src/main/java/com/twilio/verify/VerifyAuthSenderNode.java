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

import static org.forgerock.openam.auth.node.api.Action.send;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;

import com.twilio.Twilio;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import java.util.List;
import java.util.ResourceBundle;
import org.forgerock.util.i18n.PreferredLocales;
import javax.inject.Inject;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import java.util.ArrayList;
import java.util.Arrays;
import org.forgerock.util.i18n.PreferredLocales;
import java.util.Collections;
import org.forgerock.json.JsonValue;
/**
 * Twilio Verify Sender Node
 */
@Node.Metadata(outcomeProvider =  VerifyAuthSenderNode.OutcomeProvider.class,
        configClass = VerifyAuthSenderNode.Config.class, tags = {"multi-factor authentication", "marketplace", "trustnetwork"})
public class VerifyAuthSenderNode extends AbstractDecisionNode {

    static final String SERVICE_SID = "serviceSID";
    private static final String BUNDLE = "com/twilio/verify/VerifyAuthSenderNode";
    private final Logger logger = LoggerFactory.getLogger(VerifyAuthSenderNode.class);
    private final Config config;
    private String loggerPrefix = "[Twilio Auth Sender Node][Partner] ";

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The unique string to identify the Account in the Twilio account dashboard.
         */
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

        /**
         * The unique string to identify the Service in the Twilio account dashboard.
         */
        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        default String serviceSID() {
            return "";
        }

        /**
         * The authentication token found in the Twilio account dashboard.
         */
        @Attribute(order = 400)
        default Module channel() {
            return Module.SMS;
        }

        /**
         * Enable whether the node should collect the channel identifier.
         */
        @Attribute(order = 500)
        default boolean requestIdentifier() {
            return false;
        }

        @Attribute(order = 600)
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
    public VerifyAuthSenderNode(@Assisted Config config) {
        this.config = config;
        Twilio.init(config.accountSID(), String.valueOf(config.authToken()));
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug(loggerPrefix + "Started");
        try {
            ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
            String userIdentifier = context.sharedState.get(config.identifierSharedState()).asString();
            if (null == userIdentifier && config.requestIdentifier()) {
                boolean isPhone = config.channel().currentChannel() == "sms" ||
                        config.channel().currentChannel() == "call" || config.channel().currentChannel() == "whatsapp";
                if (context.hasCallbacks() && context.getCallback(NameCallback.class).isPresent()) {
                    String callbackValue = context.getCallback(NameCallback.class).get().getName();
                    userIdentifier = isPhone ? "+" + callbackValue.replaceAll("[\\D]", "") : callbackValue;
                    logger.debug(loggerPrefix + "User Identifier is {}", userIdentifier);
                } else {
                    String key = isPhone ? "phoneNumber" : "email";
                    return send(Arrays.asList(new TextOutputCallback(TextOutputCallback.INFORMATION,
                                                                     bundle.getString("callback." + key + "Text")),
                                              new NameCallback(bundle.getString("callback." + key), config.identifierSharedState())))
                            .build();
                }

            }
            Verification.creator(config.serviceSID(), userIdentifier, config.channel().currentChannel()).create();
            return Action.goTo("true").replaceSharedState(
                    context.sharedState.put(SERVICE_SID, config.serviceSID()).put(config.identifierSharedState(), userIdentifier)).build();
        } catch(Exception ex) {
            logger.error(loggerPrefix + "Exception occurred" + ex.getMessage());
            ex.printStackTrace();
            context.sharedState.put("Exception", ex.toString());
            return Action.goTo("error").build();
        }
    }

    public enum Module {
        SMS("sms"),
        CALL("call"),
        EMAIL("email"),
        WHATSAPP("whatsapp");

        private final String currentChannel;

        Module(String currentChannel) {
            this.currentChannel = currentChannel;
        }

        public String currentChannel() {
            return currentChannel;
        }
    }
    public static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        /**
         * Outcomes Ids for this node.
         */
        static final String SUCCESS_OUTCOME = "true";
        static final String ERROR_OUTCOME = "error";
        private static final String BUNDLE = VerifyAuthSenderNode.class.getName();

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

            List<Outcome> results = new ArrayList<>(
                    Arrays.asList(
                            new Outcome(SUCCESS_OUTCOME, "True")
                    )
            );
            results.add(new Outcome(ERROR_OUTCOME, "Error"));

            return Collections.unmodifiableList(results);
        }
    }
}
