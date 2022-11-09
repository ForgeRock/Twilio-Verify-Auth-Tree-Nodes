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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import java.util.Set;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import com.sun.identity.idm.AMIdentity;
import org.forgerock.json.JsonValue;
import java.util.Arrays;
import org.forgerock.util.i18n.PreferredLocales;
import java.util.Collections;

/**
 * Twilio Verify Collector Decision Node
 */
@Node.Metadata(outcomeProvider = VerifyAuthIdentifierNode.OutcomeProvider.class,
        configClass = VerifyAuthIdentifierNode.Config.class, tags = {"multi-factor authentication", "marketplace", "trustnetwork"})
public class VerifyAuthIdentifierNode extends AbstractDecisionNode {
    private final Logger logger = LoggerFactory.getLogger(VerifyAuthIdentifierNode.class);
    private final Config config;
    private String loggerPrefix = "[Twilio Identifier Node][Partner] ";
    private final CoreWrapper coreWrapper;

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String identifierAttribute() {
            return "";
        }
        @Attribute(order = 200)
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
    public VerifyAuthIdentifierNode(@Assisted Config config, CoreWrapper coreWrapper) {
        this.coreWrapper = coreWrapper;
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug(loggerPrefix + "Started");
        try {
            ActionBuilder action;
            action = Action.goTo("true");
            String username = context.sharedState.get(USERNAME).asString();
            String userIdentifier = null;
            Set<String> identifiers;
            logger.debug(loggerPrefix + "Grabbing user identifiers for " + config.identifierAttribute());
            identifiers = coreWrapper.getIdentity(username,coreWrapper.convertRealmPathToRealmDn(context.sharedState.get(REALM).asString())).getAttribute(config.identifierAttribute());
            if (identifiers != null && !identifiers.isEmpty()) {
                userIdentifier = identifiers.iterator().next();
                logger.debug(loggerPrefix + "User identifier found: " + userIdentifier);
            } else {
                action = Action.goTo("false");
                return action.build();
            }
            JsonValue copyState = context.sharedState.copy().put(config.identifierSharedState(), userIdentifier);
            return action.replaceSharedState(copyState).build();
        } catch (Exception e) {
            logger.error(loggerPrefix + "Exception occurred" + e.getMessage());
            e.printStackTrace();
            context.sharedState.put("Exception", e.toString());
            ActionBuilder action;
            action = Action.goTo("error");
            return action.build();
        }
    }

    public static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        /**
         * Outcomes Ids for this node.
         */
        static final String SUCCESS_OUTCOME = "true";
        static final String ERROR_OUTCOME = "error";
        static final String FALSE_OUTCOME = "false";
        private static final String BUNDLE = VerifyAuthIdentifierNode.class.getName();

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

            List<Outcome> results = new ArrayList<>(
                    Arrays.asList(
                            new Outcome(SUCCESS_OUTCOME, "True")
                    )
            );
            results.add(new Outcome(FALSE_OUTCOME, "False"));
            results.add(new Outcome(ERROR_OUTCOME, "Error"));

            return Collections.unmodifiableList(results);
        }
    }
}
