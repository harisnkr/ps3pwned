package com.compsec.ps3pwned.services;

import com.compsec.ps3pwned.math.ScalarMultiply;
import com.compsec.ps3pwned.math.Utils;
import com.compsec.ps3pwned.models.*;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonReader;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.compsec.ps3pwned.math.Utils.objectToJSON;

@Slf4j
@Service
public class CrackLogic {

    static JSONBody fromUOL;
    static ECParameters parameters;
    static BigInteger privateKey;
    static String srn;

    public String doAll(String toCrack) throws Exception {
        long startTime = System.nanoTime();
        srn = toCrack;
        URL url = new URL("http://foley.gold.ac.uk/cw21/api/cw2/" + srn);
        log.info("GET request to UOL: " + url);
        try (InputStream in = url.openStream()) {
            if (!Files.exists(Paths.get(srn + ".json")))
                Files.copy(in, Paths.get(srn + ".json"));
        }
        readFiles();
        performVerificationForStep1();
        getPrivateKey(findMessagesWithRepeatingRComponent());
        impersonateForStep2();
        writeToFile();
        Utils.timer(startTime);
        return objectToJSON(fromUOL);
    }

    private static void writeToFile() {
        String filename = String.format("%s_%s_CO3326cw2.json", fromUOL.getName().replaceAll("\\s", ""), fromUOL.getSrn());
        try (FileWriter writer = new FileWriter(filename)) {
            new GsonBuilder().setPrettyPrinting().create().toJson(fromUOL, writer);
        } catch (IOException e) {
            e.printStackTrace();
        }
        log.info("also saved as: {} in filesystem", filename);

    }

    private static void readFiles() throws Exception {
        fromUOL = new GsonBuilder().create().fromJson(new JsonReader(new FileReader(srn + ".json")), JSONBody.class);
        parameters = ECParameters.builder()
                .p("115792089237316195423570985008687907853269984665640564039457584007908834671663")
                .a("0")
                .b("7")
                .g(new KeyCoordinates("55066263022277343669578718895168534326250603453777594175500187360389116729240",
                        "32670510020758816978083085130507043184471273380659243275938904335757337482424"))
                .n("115792089237316195423570985008687907852837564279074904382605163141518161494337")
                .build();
    }

    static void impersonateForStep2() throws Exception {

        List<String> toSign = Arrays.asList("Neal Koblitz", "Victor Miller", "Taher Elgamal", "Whitfield Diffie", "Martin Hellman");
        List<com.compsec.ps3pwned.models.Message> currentMessages = fromUOL.getSignedMessages();
        ECPoint g = new ECPoint(new BigInteger(parameters.getG().getX()),
                new BigInteger(parameters.getG().getY()));

        BigInteger r, s, t, k;

        for (String message : toSign) {
            do {
                do {
                    k = Utils.generateRandomNumber(new BigInteger(parameters.getN()));
                    ECPoint kG = ScalarMultiply.scalmult(g, k);
                    r = kG.getAffineX().mod(new BigInteger(parameters.getN()));

                } while (r.equals(BigInteger.ZERO));
                t = k.modInverse(new BigInteger(parameters.getN()));
                BigInteger e = Utils.encodeToBI(Utils.applySHA256(message));
                BigInteger dr = privateKey.multiply(r)
                        .mod(new BigInteger(parameters.getN()));
                BigInteger ePlusDr = e.add(dr);
                s = t.multiply(ePlusDr).mod(new BigInteger(parameters.getN()));

            } while (s.equals(BigInteger.ZERO));

            currentMessages.add(
                    new Message(message, new SignatureCoordinates(r.toString(), s.toString()))
            );
        }
        performVerificationForStep2(currentMessages);
    }

    private static void getPrivateKey(List<Message> messages) {
        if (messages.size() > 2)
            messages.subList(0, 2);

        Message first = messages.get(0);
        Message second = messages.get(1);

        BigInteger z1s2 = Utils.encodeToBI(Utils.applySHA256(first.getText()))
                .multiply(new BigInteger(second.getSignature().getS()));

        BigInteger z2s1 = Utils.encodeToBI(Utils.applySHA256(second.getText()))
                .multiply(new BigInteger(first.getSignature().getS()));

        BigInteger s1r2 = new BigInteger(first.getSignature().getS())
                .multiply(new BigInteger(second.getSignature().getR()));

        BigInteger s2r1 = new BigInteger(second.getSignature().getS())
                .multiply(new BigInteger(first.getSignature().getR()));

        BigInteger numerator = z1s2.subtract(z2s1).mod(new BigInteger(parameters.getN()));
        BigInteger denominator = s1r2.subtract(s2r1).mod(new BigInteger(parameters.getN()));
        BigInteger inverseDenominator = denominator.modInverse(new BigInteger(parameters.getN()));
        privateKey = numerator.multiply(inverseDenominator).mod(new BigInteger(parameters.getN()));

        KeyCoordinates keyCoordinates = fromUOL.getAlice().getPublicKey();
        fromUOL.setAlice(new Credentials(privateKey.toString(), keyCoordinates));

    }

    private static List<Message> findMessagesWithRepeatingRComponent() {
        return fromUOL.getSignedMessages()
                .stream()
                .collect(
                        Collectors.groupingBy(t -> t.getSignature().getR(), Collectors.mapping(Function.identity(), Collectors.toList()))
                )
                .values()
                .stream()
                .filter(i -> i.size() > 1)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }

    static void performVerificationForStep2(List<Message> messagesToVerify) throws Exception {
        for (Message message : messagesToVerify) {
            String eAsString = Utils.applySHA256(message.getText());
            BigInteger m = Utils.encodeToBI(eAsString);
            BigInteger r = new BigInteger(message.getSignature().getR());
            BigInteger s = new BigInteger(message.getSignature().getS());
            BigInteger n = new BigInteger(parameters.getN());
            BigInteger w = s.modInverse(n);
            BigInteger u1 = m.multiply(w).mod(n);
            BigInteger u2 = r.multiply(w).mod(n);

            ECPoint q = new ECPoint(new BigInteger(fromUOL.getAlice().getPublicKey().getX()),
                    new BigInteger(fromUOL.getAlice().getPublicKey().getY()));

            ECPoint g = new ECPoint(new BigInteger(parameters.getG().getX()),
                    new BigInteger(parameters.getG().getY()));

            ECPoint u1g = ScalarMultiply.scalmult(g, u1);
            ECPoint u2q = ScalarMultiply.scalmult(q, u2);
            ECPoint x = ScalarMultiply.addPoint(u1g, u2q);
            BigInteger v = x.getAffineX().mod(n);

            if (v.equals(r)) {
                log.info("signature of \"" + message.getText() + "\"" + " has been verified");
            }
        }
    }

    static void performVerificationForStep1() {

        List<Message> messagesToVerify = fromUOL.getSignedMessages();
        List<Message> messageList = new ArrayList<>();

        for (Message message : messagesToVerify) {
            String eAsString = Utils.applySHA256(message.getText());
            BigInteger m = Utils.encodeToBI(eAsString);
            BigInteger r = new BigInteger(message.getSignature().getR());
            BigInteger s = new BigInteger(message.getSignature().getS());
            BigInteger n = new BigInteger(parameters.getN());
            BigInteger w = s.modInverse(n);
            BigInteger u1 = m.multiply(w).mod(n);
            BigInteger u2 = r.multiply(w).mod(n);

            ECPoint q = new ECPoint(new BigInteger(fromUOL.getAlice().getPublicKey().getX()),
                    new BigInteger(fromUOL.getAlice().getPublicKey().getY()));

            ECPoint g = new ECPoint(new BigInteger(parameters.getG().getX()),
                    new BigInteger(parameters.getG().getY()));

            ECPoint u1g = ScalarMultiply.scalmult(g, u1);
            ECPoint u2q = ScalarMultiply.scalmult(q, u2);
            ECPoint x = ScalarMultiply.addPoint(u1g, u2q);
            BigInteger v = x.getAffineX().mod(n);

            if (v.equals(r)) {
                messageList.add(message);
//                log.info("\"" + message.getText() + "\"" + " has been verified");
            }
        }

        fromUOL.setSignedMessages(messageList);

    }

}
