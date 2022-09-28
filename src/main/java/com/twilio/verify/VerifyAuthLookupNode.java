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
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.forgerock.openam.sm.annotations.adapters.Password;
import com.google.common.base.Strings;
import com.google.inject.assistedinject.Assisted;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import com.twilio.rest.lookups.v1.PhoneNumber;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import com.twilio.Twilio;

/**
 * Twilio Verify Collector Decision Node
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = VerifyAuthLookupNode.Config.class, tags = {"mfa", "multi-factor authentication", "marketplace", "trustnetwork"})
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
        String phoneNumber = context.sharedState.get("userIdentifier").asString();
        PhoneNumber number = PhoneNumber
                    .fetcher(new com.twilio.type.PhoneNumber(phoneNumber))
                    .fetch();

        String carrier = number.getCarrier().get("type");
        try {
             String type =  number.getCarrier().get("type");
             if (type != "mobile") {
                return goTo(false).build();
             }
        } catch(Exception ex) {
            logger.error(loggerPrefix + e.printStackTrace().toString());
        }
        return goTo(true).build();
    }


}
