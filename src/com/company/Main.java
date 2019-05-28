package com.company;
import java.math.*;
import java.util.ArrayList;
import java.util.List;

public class Main {

    private static void testPaillier() {

        //实例化一个不用传参的对象，用默认的数据
        Paillier paillier = new Paillier();

        // 实例化两个数据对象m1,m2，进行加密
        BigInteger m1 = new BigInteger("20");
        BigInteger m2 = new BigInteger("60");

        //加密
        BigInteger em1 = paillier.Encryption(m1);
        BigInteger em2 = paillier.Encryption(m2);

        System.out.println("==Test1: D(E(m1))=m1, D(E(m2))=m2?===================================================");
        System.out.println("m1 = " + m1.toString());
        System.out.println("E(m1) = " + em1.toString());
        System.out.println("D(E(m1)) = " + paillier.Decryption(em1).toString());
        System.out.println("m2 = " + m2.toString());
        System.out.println("E(m2) = " + em2.toString());
        System.out.println("D(E(M2)) = " + paillier.Decryption(em2).toString());
        if (paillier.Decryption(em1).equals(m1) && paillier.Decryption(em2).equals(m2)) {
            System.out.println("Passed Test1");
        }
        else {
            System.out.println("Failed Test1");
        }


        // 测试同态性     D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n

        // m1+m2,求明文数值的和, mod n
        BigInteger sum_m1_m2 = m1.add(m2).mod(paillier.n);
        // em1+em2，求密文数值的乘, mod n^2
        BigInteger product_em1_em2 = em1.multiply(em2).mod(paillier.nsquare);

        System.out.println("==Test2: D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n?===================================");
        System.out.println("(m1 + m2) mod n = " + sum_m1_m2.toString());
        System.out.println("E(m1) * E(m2) mod n^2 = " + product_em1_em2.toString());
        System.out.println("D(E(m1)*E(m2) mod n^2) = "+ paillier.Decryption(product_em1_em2).toString());
        if (paillier.Decryption(product_em1_em2).equals(sum_m1_m2)) {
            System.out.println("Passed Test2");
        }
        else {
            System.out.println("Failed Test2");
        }

        // 测试同态性 ->   D(E(m1)^m2 mod n^2) = (m1*m2) mod n
        // m1*m2,求明文数值的乘, mod n
        BigInteger prod_m1_m2 = m1.multiply(m2).mod(paillier.n);
        // em1的m2次方, mod n^2
        BigInteger expo_em1_m2 = em1.modPow(m2, paillier.nsquare);

        System.out.println("==Test3: D(E(m1)^m2 mod n^2) = (m1 * m2) mod n?======================================");
        System.out.println("(m1 * m2) mod n = " + prod_m1_m2.toString());
        System.out.println("E(m1)^m2 mod n^2 = " + expo_em1_m2.toString());
        System.out.println("D(E(m1)^m2 mod n^2) = "+ paillier.Decryption(expo_em1_m2).toString());
        if (paillier.Decryption(expo_em1_m2).equals(prod_m1_m2)) {
            System.out.println("Passed Test3");
        }
        else {
            System.out.println("Failed Test3");
        }
    }

    private static void testCounter() {

        //实例化一个不用传参的对象，用默认的数据
        Paillier paillier = new Paillier();
        Counter counter = new Counter(paillier);
        List<BigInteger> public_key = counter.GetPublicKey();

        //模拟投票：
        //      投票者: voter1， voter2
        //      候选人：candidate1， candidate2
        //      计票者：counter
        //      公布者：publisher

        // 投票者明文票型
        System.out.println("==Test Voting Counter================================================================");
        List<BigInteger> voter1_m = new ArrayList<>();
        voter1_m.add(BigInteger.valueOf(2));
        voter1_m.add(BigInteger.valueOf(0));
        System.out.println("voter1_m = " + voter1_m.toString());
        List<BigInteger> voter2_m = new ArrayList<>();
        voter2_m.add(BigInteger.valueOf(1));
        voter2_m.add(BigInteger.valueOf(1));
        System.out.println("voter2_m = " + voter2_m.toString());
        List<BigInteger> voter1_em = new ArrayList<>();
        for (int i = 0;i < voter1_m.size();i++) {
            voter1_em.add(paillier.EncryptionWithPublicKey(voter1_m.get(i), public_key.get(0), public_key.get(1), public_key.get(2).intValue()));
        }
        List<BigInteger> voter2_em = new ArrayList<>();
        for (int i = 0;i < voter2_m.size();i++) {
            voter2_em.add(paillier.EncryptionWithPublicKey(voter2_m.get(i), public_key.get(0), public_key.get(1), public_key.get(2).intValue()));
        }
        System.out.println("voter1_em = " + voter1_em.toString());
        System.out.println("voter2_em = " + voter2_em.toString());
        List<List<BigInteger>> input_em = new ArrayList<List<BigInteger>>();
        input_em.add(voter1_em);
        input_em.add(voter2_em);
        List<BigInteger> res_em = counter.MergeVoting(input_em);
        System.out.println("res_em = " + res_em.toString());
        List<BigInteger> res = new ArrayList<>();
        boolean pass = true;
        for (int i = 0;i < res_em.size();i++) {
            res.add(paillier.Decryption(res_em.get(i)));
            if (!res.get(i).equals(voter1_m.get(i).add(voter2_m.get(i).mod(paillier.n)))){
                pass = false;
            }
        }
        System.out.println("res = " + res.toString());
        if (pass) {
            System.out.println("Passed Test");
        }
        else {
            System.out.println("Failed Test");
        }

    }

    public static void main(String[] args) {
        // write your code here
        testPaillier();
        testCounter();
    }
}
