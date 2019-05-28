package com.company;
import java.math.*;
import java.util.*;


/* Paillier 加密算法
 * 密钥生成：
 * 1、随机选择两个大质数p和q满足gcd（pq,(p-1)(q-1)）=1。 这个属性是保证两个质数长度相等。
 * 2、计算 n = pq和λ= lcm (p - 1,q-1)。
 * 3、选择随机整数g使得gcd(L(g^lambda % n^2) , n) = 1,满足g属于n^2;
 * 4、公钥为（n，g）
 * 5、私钥为lambda。
 * :加密
 * 选择随机数r，长度为bitlength
 * 计算密文
 * 其中m为加密信息
 *
 * 解密：
 * m = D(c,lambda) = ( L(c^lambda%n^2)/L(g^lambda%n^2) )%n;
 * 其中L(u) = (u-1)/n;
 */


public class Paillier {
    private BigInteger p, q, lambda;
    public BigInteger n, nsquare, g;
    public int bitLength;

    public Paillier(int bitLengthVal, int certainty) {
        for (int i = 0;i < 1000;i++) {
            if (KeyGeneration(bitLengthVal, certainty)) {
                return;
            }
        }
        System.out.println("Can not generate proper key!");
        System.exit(1);
    }

    public Paillier() {
        for (int i = 0;i < 1000;i++) {
            if (KeyGeneration(512, 64)) {
                return;
            }
        }
        System.out.println("Can not generate proper key!");
        System.exit(1);
    }

    /**
     * Generate public key: n,g       secret key: lamada
     * @param bitLengthVal
     *            number of bits of modulus.
     * @param certainty
     *            The probability that the new BigInteger represents a prime
     *            number will exceed (1 - 2^(-certainty)). The execution time of
     *            this constructor is proportional to the value of this
     *            parameter.
     */
    public boolean KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        //构造两个随机生成的正大质数
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());
        n = p.multiply(q);
        nsquare = n.multiply(n);
        for(int i = 0;i < 10000;i++) {
            g = new BigInteger(String.valueOf((int)(Math.random()*100)));

            //lamada=lcm(p-1,q-1)=((p-1)*(q-1)) / gcd(p-1,q-1)
            lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))  //(p-1)*(q-1)
                    .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
            //Test: gcd (L(g^lambda mod nsquare), n) = 1?
            if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() == 1) {
                return true;
            }
        }
        return false;
    }

    public BigInteger Encryption(BigInteger m, BigInteger r) {
        //c = (g^m)*(r^n)modnsquare
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    public BigInteger Encryption(BigInteger m) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    public BigInteger EncryptionWithPublicKey(BigInteger m, BigInteger r, BigInteger _n, BigInteger _g) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        BigInteger _nsquare = _n.multiply(_n);
        return _g.modPow(m, _nsquare).multiply(r.modPow(_n, _nsquare)).mod(_nsquare);
    }

    public BigInteger EncryptionWithPublicKey(BigInteger m, BigInteger _n, BigInteger _g, int _bitLength) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        BigInteger r = new BigInteger(_bitLength, new Random());
        BigInteger _nsquare = _n.multiply(_n);
        return _g.modPow(m, _nsquare).multiply(r.modPow(_n, _nsquare)).mod(_nsquare);
    }

    public BigInteger Decryption(BigInteger c) {
        BigInteger u1 = c.modPow(lambda, nsquare);
        BigInteger u2 = g.modPow(lambda, nsquare);
        return (u1.subtract(BigInteger.ONE).divide(n)).multiply(u2.subtract(BigInteger.ONE).divide(n).modInverse(n)).mod(n);
    }
}
