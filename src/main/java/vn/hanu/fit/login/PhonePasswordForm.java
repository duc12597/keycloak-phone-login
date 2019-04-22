package vn.hanu.fit.login;

import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class PhonePasswordForm extends AbstractUsernameFormAuthenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();

        LoginFormsProvider forms = context.form();
        if (formData.size() > 0)
            forms.setFormData(formData);

        context.challenge(forms.createForm(KeycloakUtil.TEMPLATE));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, context.form().createForm(KeycloakUtil.TEMPLATE));
            return;
        }
        context.success();
    }

    private boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        // check null input
        String input = inputData.getFirst(KeycloakUtil.FIELD_EMAIL_PHONE);
        if (input == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = invalidUser(context);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        }
        input = input.trim();
        context.getEvent().detail(KeycloakUtil.FIELD_EMAIL_PHONE, input);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, input);

        // check duplicate
        UserModel user;
        try {
            if (input.contains("@")) {
                user = context.getSession().users().getUserByEmail(input, context.getRealm());
            } else {
                user = KeycloakUtil.searchByPhone(context.getSession().users().getUsers(context.getRealm()), input);
            }
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);
            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }
            return false;
        }

        if (invalidUser(context, user) || !validatePassword(context, user, inputData) || !enabledUser(context, user))
            return false;

        context.setUser(user);
        return true;
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {}

}
