package com.company;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;


/* 基于Paillier的匿名电子投票算法
 * 基站1具有：公钥 n, g, 密钥 lambda，模量 bit_length
 * 基站1可以是某一个降落者，服务器或是补给箱
 * 基站1将自己的公钥和模量发送给投票者，
 * 投票者对自己的投票结果使用基站的公钥进行加密，发送给基站2（基站2是异于基站1的成员），基站2统计加密后的信息后发送给基站1
 * 基站1对统计信息进行解密，将投票结果反馈给所有成员（投票者）
 * 若要更好地理解流程，可参照博客：https://www.jianshu.com/p/839333eb5a4d
 */

public class Counter {
    public BigInteger n, nsquare, g;
    public int bitLength;
    public Counter(Paillier p){
        n = p.n;
        nsquare = p.nsquare;
        g = p.g;
        bitLength = p.bitLength;
    }
    public List<BigInteger> GetPublicKey() {
        List<BigInteger> res = new ArrayList<>();
        res.add(n);
        res.add(g);
        res.add(BigInteger.valueOf(bitLength));
        return res;
    }
    public List<BigInteger> MergeVoting(List<List<BigInteger>> val){
        List<BigInteger> res = new ArrayList<>();
        int size = val.size();
        if (size > 0) {
            int num = val.get(0).size();
            for (int i = 0;i < num;i++) {
                res.add(BigInteger.valueOf(1));
            }
            for (int i = 0;i < size;i++) {
                if (val.get(i).size() != num) {
                    continue;
                }
                for (int j = 0;j < num;j++){
                    res.set(j, res.get(j).multiply(val.get(i).get(j)).mod(nsquare));
                }
            }
        }
        return res;
    }
}
