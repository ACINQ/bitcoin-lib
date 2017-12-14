package org.bitcoin;

/**
 * Created by fabrice on 15/06/17.
 */
public class Preconditions {
    private Preconditions() {
    }

    public static void checkArgument(boolean expression) {
        if (!expression) {
            throw new IllegalArgumentException();
        }
    }
}
