package vn.hanu.fit.login;

import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;

import java.util.List;

public class KeycloakUtil {

    public static final String PHONE = "phoneNumber";
    public static final String FIELD_PHONE = Constants.USER_ATTRIBUTES_PREFIX + PHONE;
    public static final String FIELD_EMAIL_PHONE = "email-phone";
    public static final String TEMPLATE = "login-phone.ftl";

    public static UserModel searchByPhone(List<UserModel> allUsers, String phone) {
        for (UserModel user : allUsers)
            if (phone.equals(getPhoneNumber(user)))
                return user;

        return null;
    }

    public static String getPhoneNumber(UserModel user) {
        try {
            return user.getFirstAttribute(PHONE);
        } catch (NullPointerException e) {
            return "";
        }
    }
}
