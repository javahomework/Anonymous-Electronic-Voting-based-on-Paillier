package com.company;
import java.math.*;
import java.util.ArrayList;
import java.util.List;

public class Main {

    private static void testPaillier() {

        //实例化一个不用传参的对象，用默认的数据
        Paillier paillier = new Paillier();
        List<BigInteger> public_key = paillier.GetPublicKey();

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
        BigInteger sum_m1_m2 = m1.add(m2).mod(public_key.get(0));
        // em1+em2，求密文数值的乘, mod n^2
        BigInteger product_em1_em2 = em1.multiply(em2).mod(public_key.get(1));

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
        BigInteger prod_m1_m2 = m1.multiply(m2).mod(public_key.get(0));
        // em1的m2次方, mod n^2
        BigInteger expo_em1_m2 = em1.modPow(m2, public_key.get(1));

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
        Counter counter = new Counter(paillier, true);
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
            voter1_em.add(paillier.EncryptionWithPublicKey(voter1_m.get(i), public_key));
        }
        List<BigInteger> voter2_em = new ArrayList<>();
        for (int i = 0;i < voter2_m.size();i++) {
            voter2_em.add(paillier.EncryptionWithPublicKey(voter2_m.get(i), public_key));
        }
        System.out.println("voter1_em = " + voter1_em.toString());
        System.out.println("voter2_em = " + voter2_em.toString());
        counter.InitMergeVoting();
        counter.MergeVoting(voter1_em);
        counter.MergeVoting(voter2_em);
        List<BigInteger> res_em = counter.GetMergeVotingResult();
        System.out.println("res_em = " + res_em.toString());
        List<BigInteger> res = new ArrayList<>();
        boolean pass = true;
        for (int i = 0;i < res_em.size();i++) {
            res.add(paillier.Decryption(res_em.get(i)));
            if (!res.get(i).equals(voter1_m.get(i).add(voter2_m.get(i).mod(public_key.get(0))))){
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

    private static boolean BigIntegerListEquals(List<BigInteger> list1, List<BigInteger> list2) {
        if (list1.size() != list2.size()) {
            return false;
        }
        for (int i = 0;i < list1.size();i++) {
            if (!list1.get(i).equals(list2.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static void testHelper() {
        Paillier paillier = new Paillier();
        List<BigInteger> public_key = paillier.GetPublicKey();
        List<BigInteger> voter1_m = new ArrayList<>();
        voter1_m.add(BigInteger.valueOf(2));
        voter1_m.add(BigInteger.valueOf(0));
        Counter voter1 = new Counter(public_key); // 投票者1，无密钥
        List<BigInteger> voter1_em = voter1.Encryption(voter1_m);
        byte[] byte_public_key = Helper.BigIntegetListToBytes(public_key);
        byte[] byte_voter1_m = Helper.BigIntegetListToBytes(voter1_m);
        byte[] byte_voter1_em = Helper.BigIntegetListToBytes(voter1_em);
        List<BigInteger> covered_public_key = Helper.BytesToBigIntegetList(byte_public_key);
        List<BigInteger> covered_voter1_m = Helper.BytesToBigIntegetList(byte_voter1_m);
        List<BigInteger> covered_voter1_em = Helper.BytesToBigIntegetList(byte_voter1_em);
        System.out.println("public_key = " + public_key.toString());
        System.out.println("covered_public_key = " + covered_public_key.toString());
        System.out.println("voter1_m = " + voter1_m.toString());
        System.out.println("covered_voter1_m = " + covered_voter1_m.toString());
        System.out.println("voter1_em = " + voter1_em.toString());
        System.out.println("covered_voter1_em = " + covered_voter1_em.toString());
        if (!BigIntegerListEquals(public_key, covered_public_key)) {
            System.out.println("public_key error");
        }
        if (!BigIntegerListEquals(voter1_m, covered_voter1_m)) {
            System.out.println("voter1_m error");
        }
        if (!BigIntegerListEquals(voter1_em, covered_voter1_em)) {
            System.out.println("voter1_em error");
        }
        System.out.println("All correct");
    }

    private static void workFlow(){

        //模拟投票：
        //      投票者: voter1， voter2（拥有公钥）
        //      候选人：candidate1， candidate2（拥有公钥）
        //      计票者：counter（拥有公钥，可参与投票）
        //      公布者：publisher（拥有公钥和密钥，可参与投票）

        //实例化一个不用传参的加密器
        Paillier paillier = new Paillier();
        byte[] bytes_public_key = paillier.GetBytesPublicKey();
        // 传入一个参数Paillier
//        Counter counter = new Counter(paillier, false); //可控制有无密钥
        //或者不传参
        // Counter counter = new Counter(); //无密钥类型

        // 投票者明文票型
        System.out.println("==Test Voting Counter================================================================");

        // 投票者 voter1
        List<BigInteger> voter1_m = new ArrayList<>();
        voter1_m.add(BigInteger.valueOf(2));
        voter1_m.add(BigInteger.valueOf(0));
        System.out.println("voter1_m = " + voter1_m.toString());
        Counter voter1 = new Counter(bytes_public_key); // 投票者1，无密钥

        // 投票者 voter2
        List<BigInteger> voter2_m = new ArrayList<>();
        voter2_m.add(BigInteger.valueOf(1));
        voter2_m.add(BigInteger.valueOf(1));
        System.out.println("voter2_m = " + voter2_m.toString());
        Counter voter2 = new Counter(bytes_public_key); // 投票者2，无密钥

        // 投票者 voter3
        List<BigInteger> voter3_m = new ArrayList<>();
        voter3_m.add(BigInteger.valueOf(0));
        voter3_m.add(BigInteger.valueOf(2));
        System.out.println("voter3_m = " + voter3_m.toString());
        Counter voter3 = new Counter(bytes_public_key); // 投票者3，也是计票者，无密钥

        // 投票者 voter4
        List<BigInteger> voter4_m = new ArrayList<>();
        voter4_m.add(BigInteger.valueOf(0));
        voter4_m.add(BigInteger.valueOf(1));
        System.out.println("voter4_m = " + voter4_m.toString());
        Counter voter4 = new Counter(paillier, true); // 投票者4，也是公布者，有密钥

        // 投票者们对票型加密
        List<BigInteger> voter1_em = voter1.Encryption(voter1_m);
        List<BigInteger> voter2_em = voter1.Encryption(voter2_m);
        List<BigInteger> voter3_em = voter1.Encryption(voter3_m);
        List<BigInteger> voter4_em = voter1.Encryption(voter4_m);
        System.out.println("voter1_em = " + voter1_em.toString());
        System.out.println("voter2_em = " + voter2_em.toString());
        System.out.println("voter3_em = " + voter3_em.toString());
        System.out.println("voter4_em = " + voter4_em.toString());

        // 投票者们将加密后的票型发送给投票者3，即计票者，计票者进行统计
        voter3.InitMergeVoting();
        voter3.MergeVoting(voter1_em);
        voter3.MergeVoting(voter2_em);
        voter3.MergeVoting(voter3_em);
        voter3.MergeVoting(voter4_em);
        List<BigInteger> res_em = voter3.GetMergeVotingResult();
        System.out.println("res_em = " + res_em.toString());

        //计票者将统计结果发送给公布者，公布者进行解密，公布结果
        List<BigInteger> res = voter4.Decryption(res_em);
        System.out.println("res = " + res.toString());
    }

    public static void main(String[] args) {
        // write your code here
        testHelper();
        testPaillier();
        testCounter();
        workFlow();
    }
}
