package com.compsec.ps3pwned.math;

import java.math.BigInteger;
import java.security.spec.ECPoint;

public class ScalarMultiply {

    private static final BigInteger ONE = new BigInteger("1");
    static BigInteger TWO = new BigInteger("2");
    static BigInteger p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663");
    static BigInteger a = new BigInteger("0");


    public static ECPoint scalmult(ECPoint P, BigInteger kin) {
        ECPoint R = ECPoint.POINT_INFINITY, S = P;
        BigInteger k = kin.mod(p);
        int length = k.bitLength();
        byte[] binarray = new byte[length];
        for (int i = 0; i <= length - 1; i++) {
            binarray[i] = k.mod(TWO).byteValue();
            k = k.divide(TWO);
        }

        for (int i = length - 1; i >= 0; i--) {
            R = doublePoint(R);
            if (binarray[i] == 1)
                R = addPoint(R, S);
        }
        return R;
    }

    public static ECPoint addPoint(ECPoint r, ECPoint s) {
        if (r.equals(s))
            return doublePoint(r);
        else if (r.equals(ECPoint.POINT_INFINITY))
            return s;
        else if (s.equals(ECPoint.POINT_INFINITY))
            return r;
        BigInteger slope = (r.getAffineY().subtract(s.getAffineY())).multiply(r.getAffineX().subtract(s.getAffineX()).modInverse(p)).mod(p);
        BigInteger Xout = (slope.modPow(TWO, p).subtract(r.getAffineX())).subtract(s.getAffineX()).mod(p);
        BigInteger Yout = s.getAffineY().negate().mod(p);
        Yout = Yout.add(slope.multiply(s.getAffineX().subtract(Xout))).mod(p);
        ECPoint out = new ECPoint(Xout, Yout);
        return out;
    }

    public static ECPoint doublePoint(ECPoint r) {
        if (r.equals(ECPoint.POINT_INFINITY))
            return r;
        BigInteger slope = (r.getAffineX().pow(2)).multiply(new BigInteger("3"));
        slope = slope.add(a);
        slope = slope.multiply((r.getAffineY().multiply(TWO)).modInverse(p));
        BigInteger Xout = slope.pow(2).subtract(r.getAffineX().multiply(TWO)).mod(p);
        BigInteger Yout = (r.getAffineY().negate()).add(slope.multiply(r.getAffineX().subtract(Xout))).mod(p);
        ECPoint out = new ECPoint(Xout, Yout);
        return out;
    }
}