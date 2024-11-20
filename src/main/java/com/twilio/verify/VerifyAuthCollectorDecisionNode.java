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
import java.util.Arrays;
import org.forgerock.util.i18n.PreferredLocales;
import java.util.Collections;
import org.forgerock.json.JsonValue;

import javax.security.auth.callback.ConfirmationCallback;

/**
 * Twilio Verify Collector Decision Node
 */
@Node.Metadata(outcomeProvider = VerifyAuthCollectorDecisionNode.OutcomeProvider.class,
        configClass = VerifyAuthCollectorDecisionNode.Config.class, tags = {"multi-factor authentication", "marketplace", "trustnetwork"})
public class VerifyAuthCollectorDecisionNode extends AbstractDecisionNode {

    private static final String BUNDLE = "com/twilio/verify/VerifyAuthCollectorDecisionNode";
    private final Logger logger = LoggerFactory.getLogger(VerifyAuthCollectorDecisionNode.class);
    private String loggerPrefix = "[Twilio Auth Collector Decision Node][Partner] ";
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

        @Attribute(order = 200)
        default String identifierSharedState() {
            return "userIdentifier";
        }

        @Attribute(order = 300)
        default boolean showResendButton() {
            return false;
        }

        @Attribute(order = 400)
        default String resendButtonText() {
            return "resend";
        }

        @Attribute(order = 500)
        default boolean showCancelButton() {
            return false;
        }

        @Attribute(order = 600)
        default String cancelButtonText() {
            return "cancel";
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
        logger.debug(loggerPrefix + "Started");
        try {
            Optional<String> callbackCode;
            if (config.hideCode()) {
                logger.debug(loggerPrefix+ "VerifyAuthCollectorDecision code is hidden");
                callbackCode = context.getCallback(PasswordCallback.class).map(PasswordCallback::getPassword)
                                      .map(String::new);
            } else {
                logger.debug(loggerPrefix + "VerifyAuthCollectorDecision code is not hidden");
                callbackCode = context.getCallback(NameCallback.class)
                                      .map(NameCallback::getName);
            }
            Optional<ConfirmationCallback> confirmationCallback = context.getCallback(ConfirmationCallback.class);


            if(config.showResendButton() && config.showCancelButton()) { 
              if (confirmationCallback.isPresent()) {
                  int index = confirmationCallback.get().getSelectedIndex();
                  if(index == 1) {
                    return Action.goTo("resend").build();
                  }
                  else if(index==2) {
                    return Action.goTo("cancel").build();
                  }
              }
            }
            else if(config.showResendButton()) {
              if (confirmationCallback.isPresent() && confirmationCallback.get().getSelectedIndex() == 1) {
                  return Action.goTo("resend").build();
              }
            }
            
            else if (config.showCancelButton()) {
              if (confirmationCallback.isPresent() && confirmationCallback.get().getSelectedIndex() == 1) {
                  return Action.goTo("cancel").build();
              }
            }
            
            return callbackCode.filter(code -> !Strings.isNullOrEmpty(code))
                               .map(code -> checkCode(context.sharedState.get(VerifyAuthSenderNode.SERVICE_SID).asString(), code,
                                      context.sharedState.get(config.identifierSharedState()).asString()))
                               .orElseGet(() -> collectCode(context));
       } catch(Exception ex) {
             logger.error(loggerPrefix + "Exception occurred" + ex.getMessage());
             ex.printStackTrace();
             context.sharedState.put("Exception", ex.toString());
             return Action.goTo("error").build();
         }
    }


    private Action checkCode(String verifySID, String code, String userIdentifier) {
        VerificationCheck verification = VerificationCheck.creator(verifySID, code).setTo(userIdentifier).create();
        logger.debug(loggerPrefix + "Verification Status: {}", verification.getStatus());
        if ("approved".equals(verification.getStatus())) {
            return Action.goTo("true").build();
        }
        return Action.goTo("false").build();

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
        if (config.showResendButton() && config.showCancelButton()) {
          ConfirmationCallback confirmationCallbackResendCancel = new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[] {"Next", config.resendButtonText(), config.cancelButtonText()}, 1);

          callbacks.add(confirmationCallbackResendCancel);
        }

        else if (config.showResendButton()) {
          ConfirmationCallback confirmationCallbackResend = new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[] {"Next", config.resendButtonText()}, 1);
          callbacks.add(confirmationCallbackResend);

        }

        else if (config.showCancelButton()) {
          ConfirmationCallback confirmationCallbackCancel = new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[] {"Next", config.cancelButtonText()}, 1);
          callbacks.add(confirmationCallbackCancel);
        }
        
        return send(callbacks).build();
    }

    public static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        /**
         * Outcomes Ids for this node.
         */
        static final String SUCCESS_OUTCOME = "true";
        static final String ERROR_OUTCOME = "error";
        static final String FALSE_OUTCOME = "false";
        static final String RESEND_OUTCOME = "resend";
        static final String CANCEL_OUTCOME = "cancel";
        private static final String BUNDLE = VerifyAuthCollectorDecisionNode.class.getName();

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

            List<Outcome> results = new ArrayList<>(
                    Arrays.asList(
                            new Outcome(SUCCESS_OUTCOME, "True")
                    )
            );

            results.add(new Outcome(FALSE_OUTCOME, "False"));

            
            if (nodeAttributes.isNotNull()) {
                if (nodeAttributes.get("showResendButton").required().asBoolean()) {
                    results.add(new Outcome(RESEND_OUTCOME, "Resend"));
                  }
            }
            if (nodeAttributes.isNotNull()) {
                if (nodeAttributes.get("showCancelButton").required().asBoolean()) {
                  results.add(new Outcome(CANCEL_OUTCOME, "Cancel"));
                  }
            }
            
              
            results.add(new Outcome(ERROR_OUTCOME, "Error"));

            return Collections.unmodifiableList(results);
        }
    }
}
