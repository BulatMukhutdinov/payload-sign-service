package jp.co.soramitsu.util;

public class Const {

    private Const() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    // Regexps
    public static final String REGEX_ACCOUNT_NAME = "[a-z]{1,7}";
    public static final String REGEX_DOMAIN_ID = "[a-z]{1,9}";

    // Errors
    public static final String ERROR_INVALID_ARGUMENT = "Invalid field '%s'. It has to match pattern %s";
}
