package com.compsec.ps3pwned.math;

import com.google.gson.GsonBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@Slf4j
public class Utils {

    private Utils() {

    }

    public static String applySHA256(final String text) {
        return DigestUtils.sha256Hex(text);
    }

    public static BigInteger encodeToBI(final String text) {
        return new BigInteger(text.getBytes(StandardCharsets.UTF_8));
    }

    public static void timer(long runtimeClock) {
        log.info("Execution Time: " + ((System.nanoTime() - runtimeClock) / 1000000) + " milliseconds");
    }

    public static BigInteger generateRandomNumber(BigInteger n) {
        //        System.out.println("Comparing now.. " + ans.compareTo(n.subtract(BigInteger.ONE)));
        return new BigInteger(n.subtract(BigInteger.ONE).bitLength(), new SecureRandom());
    }

    public static String objectToJSON(Object o) {
        return new GsonBuilder().setPrettyPrinting().create().toJson(o);
    }

}
