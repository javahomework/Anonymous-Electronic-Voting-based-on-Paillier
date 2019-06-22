package com.company;
import java.math.*;
import java.security.SecureRandom;
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
    private BigInteger n, nsquare, g;
    private int bitLength;
    private boolean decryption;

    public Paillier(int bitLengthVal) {
        while (true) {
            if (KeyGeneration(bitLengthVal)) {
                decryption = true;
                return;
            }
        }
    }

    public Paillier() {
        while (true) {
            if (KeyGeneration(512)) {
                decryption = true;
                return;
            }
        }
    }

    public Paillier(BigInteger _n, BigInteger _nsquare, BigInteger _g, int _bitLength) {
        n = _n;
        nsquare = _nsquare;
        g = _g;
        bitLength = _bitLength;
        p = BigInteger.ONE;
        q = BigInteger.ONE;
        lambda = BigInteger.ONE;
        decryption = false;
    }

    /**
     * Generate public key: n,g       secret key: lamada
     * @param bitLengthVal
     *            number of bits of modulus.
     */
    public boolean KeyGeneration(int bitLengthVal) {
        bitLength = bitLengthVal;
        //构造两个随机生成的正大质数
        p = BigInteger.probablePrime(bitLength / 2, new SecureRandom());
        q = BigInteger.probablePrime(bitLength / 2, new SecureRandom());
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
        BigInteger r = new BigInteger(bitLength, new SecureRandom());
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    public BigInteger EncryptionWithPublicKey(BigInteger m, BigInteger r, List<BigInteger> publicKey) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        BigInteger _n = publicKey.get(0),
                _g = publicKey.get(2);
        BigInteger _nsquare = _n.multiply(_n);
        return _g.modPow(m, _nsquare).multiply(r.modPow(_n, _nsquare)).mod(_nsquare);
    }

    public BigInteger EncryptionWithBytesPublicKey(BigInteger m, BigInteger r, byte[] public_key) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        List<BigInteger> publicKey = Helper.BytesToBigIntegetList(public_key);
        BigInteger _n = publicKey.get(0),
                _g = publicKey.get(2);
        BigInteger _nsquare = _n.multiply(_n);
        return _g.modPow(m, _nsquare).multiply(r.modPow(_n, _nsquare)).mod(_nsquare);
    }

    public BigInteger EncryptionWithPublicKey(BigInteger m, List<BigInteger> publicKey) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        int _bitLength = publicKey.get(3).intValue();
        BigInteger _n = publicKey.get(0),
                _g = publicKey.get(2);
        BigInteger r = new BigInteger(_bitLength, new SecureRandom());
        BigInteger _nsquare = _n.multiply(_n);
        return _g.modPow(m, _nsquare).multiply(r.modPow(_n, _nsquare)).mod(_nsquare);
    }

    public BigInteger EncryptionWithBytesPublicKey(BigInteger m, byte[] public_key) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        List<BigInteger> publicKey = Helper.BytesToBigIntegetList(public_key);
        int _bitLength = publicKey.get(3).intValue();
        BigInteger _n = publicKey.get(0),
                _g = publicKey.get(2);
        BigInteger r = new BigInteger(_bitLength, new SecureRandom());
        BigInteger _nsquare = _n.multiply(_n);
        return _g.modPow(m, _nsquare).multiply(r.modPow(_n, _nsquare)).mod(_nsquare);
    }

    public BigInteger Decryption(BigInteger c) {
        if (decryption) {
            BigInteger u1 = c.modPow(lambda, nsquare);
            BigInteger u2 = g.modPow(lambda, nsquare);
            return (u1.subtract(BigInteger.ONE).divide(n)).multiply(u2.subtract(BigInteger.ONE).divide(n).modInverse(n)).mod(n);
        }
        return c;
    }

    public List<BigInteger> GetPublicKey() {
        List<BigInteger> res = new ArrayList<>();
        res.add(n);
        res.add(nsquare);
        res.add(g);
        res.add(BigInteger.valueOf(bitLength));
        return res;
    }

    public byte[] GetBytesPublicKey() {
        List<BigInteger> res = new ArrayList<>();
        res.add(n);
        res.add(nsquare);
        res.add(g);
        res.add(BigInteger.valueOf(bitLength));
        return Helper.BigIntegetListToBytes(res);
    }
}
