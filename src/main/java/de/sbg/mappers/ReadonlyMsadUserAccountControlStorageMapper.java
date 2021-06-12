package de.sbg.mappers;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.TxAwareLDAPUserModelDelegate;
import org.keycloak.storage.ldap.mappers.msad.UserAccountControl;

import javax.naming.AuthenticationException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * does the same stuff as the keycloak-provider, but sets the event even if the ldap is not writable
 */
public class ReadonlyMsadUserAccountControlStorageMapper extends AbstractLDAPStorageMapper {

    public static final String LDAP_PASSWORD_POLICY_HINTS_ENABLED = "ldap.password.policy.hints.enabled";

    private static final Logger logger = Logger.getLogger(ReadonlyMsadUserAccountControlStorageMapper.class);

    private static final Pattern AUTH_EXCEPTION_REGEX = Pattern.compile(".*AcceptSecurityContext error, data ([0-9a-f]*), v.*");

    public ReadonlyMsadUserAccountControlStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {

        query.addReturningReadOnlyLdapAttribute(LDAPConstants.PWD_LAST_SET);

        query.addReturningReadOnlyLdapAttribute(LDAPConstants.USER_ACCOUNT_CONTROL);
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        return new MSADUserModelDelegate(delegate, ldapUser);
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {

    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {

    }

    @Override
    public boolean onAuthenticationFailure(LDAPObject ldapUser, UserModel user, AuthenticationException ldapException, RealmModel realm) {
        String exceptionMessage = ldapException.getMessage();
        Matcher m = AUTH_EXCEPTION_REGEX.matcher(exceptionMessage);
        if (m.matches()) {
            String errorCode = m.group(1);
            return processAuthErrorCode(errorCode, user);
        } else {
            return false;
        }
    }

    protected boolean processAuthErrorCode(String errorCode, UserModel user) {
        logger.debugf("MSAD Error code is '%s' after failed LDAP login of user '%s'", errorCode, user.getUsername());

            switch (errorCode) {
                case "532":
                case "773":
                    // User needs to change his MSAD password. Allow him to login, but add UPDATE_PASSWORD required action
                    if (user.getRequiredActionsStream().noneMatch(action -> Objects.equals(action, UserModel.RequiredAction.UPDATE_PASSWORD.name()))) {
                        user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                    }
                    return true;
                case "533":
                    // User is disabled in MSAD. Set him to disabled in KC as well
                    if (user.isEnabled()) {
                        user.setEnabled(false);
                    }
                    return true;
                case "775":
                    logger.warnf("Locked user '%s' attempt to login", user.getUsername());
                    break;
        }

        return false;
    }


    protected UserAccountControl getUserAccountControl(LDAPObject ldapUser) {
        String userAccountControl = ldapUser.getAttributeAsString(LDAPConstants.USER_ACCOUNT_CONTROL);
        long longValue = userAccountControl == null ? 0 : Long.parseLong(userAccountControl);
        return new UserAccountControl(longValue);
    }

    // Update user in LDAP if "updateInLDAP" is true. Otherwise it is assumed that LDAP update will be called at the end of transaction
    protected void updateUserAccountControl(boolean updateInLDAP, LDAPObject ldapUser, UserAccountControl accountControl) {
        String userAccountControlValue = String.valueOf(accountControl.getValue());
        logger.debugf("Updating userAccountControl of user '%s' to value '%s'", ldapUser.getDn().toString(), userAccountControlValue);

        ldapUser.setSingleAttribute(LDAPConstants.USER_ACCOUNT_CONTROL, userAccountControlValue);

        if (updateInLDAP) {
            ldapProvider.getLdapIdentityStore().update(ldapUser);
        }
    }


    public class MSADUserModelDelegate extends TxAwareLDAPUserModelDelegate {

        private final LDAPObject ldapUser;

        public MSADUserModelDelegate(UserModel delegate, LDAPObject ldapUser) {
            super(delegate, ldapProvider, ldapUser);
            this.ldapUser = ldapUser;
        }

        @Override
        public boolean isEnabled() {
            boolean kcEnabled = super.isEnabled();

            if (getPwdLastSet() > 0) {
                // Merge KC and MSAD
                return kcEnabled && !getUserAccountControl(ldapUser).has(UserAccountControl.ACCOUNTDISABLE);
            } else {
                // If new MSAD user is created and pwdLastSet is still 0, MSAD account is in disabled state. So read just from Keycloak DB. User is not able to login via MSAD anyway
                return kcEnabled;
            }
        }

        @Override
        public void setEnabled(boolean enabled) {
            // Always update DB
            super.setEnabled(enabled);
        }

        @Override
        public void addRequiredAction(RequiredAction action) {
            String actionName = action.name();
            addRequiredAction(actionName);
        }

        @Override
        public void addRequiredAction(String action) {
            // Always update DB
            super.addRequiredAction(action);
        }

        @Override
        public void removeRequiredAction(RequiredAction action) {
            String actionName = action.name();
            removeRequiredAction(actionName);
        }

        @Override
        public void removeRequiredAction(String action) {
            // Always update DB
            super.removeRequiredAction(action);
        }

        @Override
        public Stream<String> getRequiredActionsStream() {
            if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE) {
                if (getPwdLastSet() == 0 || getUserAccountControl(ldapUser).has(UserAccountControl.PASSWORD_EXPIRED)) {
                    return Stream.concat(super.getRequiredActionsStream(), Stream.of(RequiredAction.UPDATE_PASSWORD.toString()))
                            .distinct();
                }
            }
            return super.getRequiredActionsStream();
        }

        protected long getPwdLastSet() {
            String pwdLastSet = ldapUser.getAttributeAsString(LDAPConstants.PWD_LAST_SET);
            return pwdLastSet == null ? 0 : Long.parseLong(pwdLastSet);
        }


    }

}