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
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.google.inject.assistedinject.Assisted;
import com.twilio.rest.verify.v2.service.VerificationCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;

/**
 * Twilio Verify Collector Decision Node
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = VerifyAuthCollectorDecisionNode.Config.class, tags = {"mfa", "multi-factor authentication", "partner"})
public class VerifyAuthCollectorDecisionNode extends AbstractDecisionNode {

    private static final String BUNDLE = "com/twilio/verify/VerifyAuthCollectorDecisionNode";
    private final Logger logger = LoggerFactory.getLogger(VerifyAuthCollectorDecisionNode.class);
    private final Config config;


    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Enable whether the one-time password should be a password.
         */
        @Attribute(order = 100)
        default boolean hideCode() {
            return true;
        }

    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public VerifyAuthCollectorDecisionNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug("VerifyAuthCollectorDecision started");
        Optional<String> callbackCode;
        if (config.hideCode()) {
            logger.debug("VerifyAuthCollectorDecision code is hidden");
            callbackCode = context.getCallback(PasswordCallback.class).map(PasswordCallback::getPassword)
                                  .map(String::new);
        } else {
            logger.debug("VerifyAuthCollectorDecision code is not hidden");
            callbackCode = context.getCallback(NameCallback.class)
                                  .map(NameCallback::getName);
        }
        return callbackCode.filter(code -> !Strings.isNullOrEmpty(code))
                           .map(code -> checkCode(context.sharedState.get(VerifyAuthSenderNode.SERVICE_SID).asString(), code,
                                  context.sharedState.get(VerifyAuthSenderNode.USER_IDENTIFIER).asString()))
                           .orElseGet(() -> collectCode(context));
    }

    private Action checkCode(String verifySID, String code, String userIdentifier) {
        VerificationCheck verification = VerificationCheck.creator(verifySID, code).setTo(userIdentifier).create();
        logger.debug("Verification Status: {}", verification.getStatus());
        if ("approved".equals(verification.getStatus())) {
            return goTo(true).build();
        }
        return goTo(false).build();

    }

    private Action collectCode(TreeContext context) {
        ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        List<Callback> callbacks = new ArrayList<Callback>() {{
            add(new TextOutputCallback(TextOutputCallback.INFORMATION, bundle.getString("callback.text")));
        }};
        if (config.hideCode()) {
            callbacks.add(new PasswordCallback(bundle.getString("callback.code"), false));
        } else {
            callbacks.add(new NameCallback(bundle.getString("callback.code")));
        }
        return send(callbacks).build();
    }
}
