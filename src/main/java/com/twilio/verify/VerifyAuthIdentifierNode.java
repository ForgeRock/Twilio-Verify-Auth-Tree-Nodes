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

import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
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
import org.forgerock.json.JsonValue;
import java.util.Arrays;
import org.forgerock.util.i18n.PreferredLocales;
import java.util.Collections;
import static org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper.getAttributeFromContext;
import static org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper.getObject;
import static org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper.getUsernameFromContext;
import static org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper.stringAttribute;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.ALL_FIELDS;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.DEFAULT_IDM_IDENTITY_ATTRIBUTE;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.DEFAULT_IDM_MAIL_ATTRIBUTE;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.EXPAND_ALL_RELATIONSHIPS;
import org.forgerock.openam.integration.idm.IdmIntegrationService;
import org.forgerock.openam.core.realms.Realm;
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

    private final IdmIntegrationService idmIntegrationService;

    private final Realm realm;

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

        @Attribute(order = 300)
        default String identityAttribute() {
            return "userName";
        }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public VerifyAuthIdentifierNode(@Assisted Config config, CoreWrapper coreWrapper, @Assisted Realm realm,
                                    IdmIntegrationService idmIntegrationService) {
        this.coreWrapper = coreWrapper;
        this.realm = realm;
        this.config = config;
        this.idmIntegrationService = idmIntegrationService;

    }

    @Override
    public Action process(TreeContext context) {
        logger.debug(loggerPrefix + "Started");
        try {
            ActionBuilder action;
            action = Action.goTo("True");
            String username = context.sharedState.get(USERNAME).asString();
            logger.debug(loggerPrefix + "Grabbing user identifiers for " + config.identifierAttribute());


            Optional<String> identity = stringAttribute(getAttributeFromContext(idmIntegrationService, context,
                    config.identityAttribute()))
                    .or(() -> stringAttribute(getUsernameFromContext(idmIntegrationService, context)));
            identity.ifPresent(id -> logger.debug("Retrieving {} {}", context.identityResource, id));

            Optional<JsonValue> managedObject = getObject(idmIntegrationService, realm, context.request.locales,
                    context.identityResource, config.identityAttribute(), identity,
                    ALL_FIELDS, EXPAND_ALL_RELATIONSHIPS);
            String userIdentifier  = managedObject.get().get(config.identifierAttribute()).asString();

            if (userIdentifier != null && !userIdentifier.isEmpty()) {
                logger.debug(loggerPrefix + "User identifier found: " + userIdentifier);
            }
            else {
                logger.debug(loggerPrefix + "User identifier not found");
                action = Action.goTo("False");
                return action.build();
             }

            JsonValue copyState = context.sharedState.copy().put(config.identifierSharedState(), userIdentifier);
            return action.replaceSharedState(copyState).build();
        } catch (Exception e) {
            logger.error(loggerPrefix + "Exception occurred" + e.getMessage());
            e.printStackTrace();
            context.sharedState.put("Exception", e.toString());
            ActionBuilder action;
            action = Action.goTo("Error");
            return action.build();
        }
    }

    public static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        /**
         * Outcomes Ids for this node.
         */
        static final String SUCCESS_OUTCOME = "True";
        static final String ERROR_OUTCOME = "Error";
        static final String NOT_FOUND_OUTCOME = "False";
        private static final String BUNDLE = VerifyAuthIdentifierNode.class.getName();

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

            List<Outcome> results = new ArrayList<>(
                    Arrays.asList(
                            new Outcome(SUCCESS_OUTCOME, SUCCESS_OUTCOME)
                    )
            );
            results.add(new Outcome(NOT_FOUND_OUTCOME, NOT_FOUND_OUTCOME));
            results.add(new Outcome(ERROR_OUTCOME, ERROR_OUTCOME));

            return Collections.unmodifiableList(results);
        }
    }
}
