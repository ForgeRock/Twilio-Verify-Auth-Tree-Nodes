/*
 * Copyright 2019-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package com.twilio.verify;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.util.i18n.PreferredLocales;
import static org.forgerock.json.JsonValue.*;
import org.forgerock.json.JsonValue;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.ResourceException.BAD_REQUEST;
import static org.forgerock.json.resource.ResourceException.NOT_FOUND;
import static org.forgerock.json.resource.ResourceException.newResourceException;
import static org.forgerock.json.resource.ResourceResponse.FIELD_CONTENT_ID;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.OBJECT_ATTRIBUTES;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.openam.auth.node.api.TreeContext;
import java.util.Optional;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import javax.security.auth.callback.Callback;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import java.util.List;
import java.util.ArrayList;
import com.twilio.verify.VerifyAuthSenderNode.Module;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.exception.ApiException;
public class VerifyAuthCollectorDecisionNodeTest {

    @Mock
    private VerifyAuthCollectorDecisionNode.Config config;

    @Mock
    private Realm realm;

    private TreeContext context;

    private VerifyAuthCollectorDecisionNode node;

   @BeforeMethod
   public void setUp() throws Exception {
       node = null;
       initMocks(this);
       when(config.identifierSharedState()).thenReturn("userIdentifier");
       node = new VerifyAuthCollectorDecisionNode(config);
   }

    @Test
    public void testProcessWithNoCallbacks() throws Exception {
      JsonValue sharedState = json(object(field("userIdentifier", "+18457412693")));
      }

    @Test
    public void testProcessWithCallbacks() throws Exception {
      JsonValue sharedState = json(object(field("userIdentifier", "+18457412693")));
      ArrayList<Callback> callbacks = new ArrayList<Callback>() {{
          add(new TextOutputCallback(TextOutputCallback.INFORMATION, "callback.key Text"));
          add(new NameCallback("duo_response"));
      }};
    }

    private TreeContext getContext() {
        return getContext(json(object()), json(object()));
    }


    private TreeContext getContext(JsonValue sharedState) {
        return new TreeContext(sharedState, json(object()), new Builder().build(), emptyList(), Optional.empty());
    }
    private TreeContext getContext(JsonValue sharedState, JsonValue transientState) {
        return new TreeContext(sharedState, transientState, new Builder().build(), emptyList(), Optional.empty());
    }
    private TreeContext getContext(JsonValue sharedState, PreferredLocales preferredLocales,
                List<? extends Callback> callbacks) {
            return new TreeContext(sharedState,
                    new Builder().locales(preferredLocales).build(), callbacks, Optional.empty());
        }

    private TreeContext getContext(JsonValue sharedState, JsonValue transientState, ExternalRequestContext request) {
        return new TreeContext(sharedState, transientState, request, emptyList(), Optional.empty());
    }




}