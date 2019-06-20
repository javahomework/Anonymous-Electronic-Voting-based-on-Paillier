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
    private Paillier paillier;
    private boolean decryption;
    private List<BigInteger> merge_voting_result;
    private int voting_num;
    public Counter(Paillier p, boolean _decryption){
        paillier = p;
        decryption = _decryption;
        merge_voting_result = null;
        voting_num = 0;
    }
    public  Counter() {
        paillier = new Paillier();
        decryption = true;
        merge_voting_result = null;
        voting_num = 0;
    }
    public List<BigInteger> GetPublicKey() {
        List<BigInteger> res = new ArrayList<>();
        res.add(paillier.n);
        res.add(paillier.g);
        res.add(BigInteger.valueOf(paillier.bitLength));
        return res;
    }
    public void InitMergeVoting() {
        merge_voting_result = null;
        voting_num = 0;
    }
    public int MergeVoting(List<BigInteger> val){
        int size = val.size();
        if (merge_voting_result == null) {
            merge_voting_result = new ArrayList<>();
            for (int i = 0;i < size;i++) {
                merge_voting_result.add(BigInteger.valueOf(1));
            }
        }
        else if (size != merge_voting_result.size()) {
            return voting_num;
        }
        voting_num++;
        for (int j = 0;j < size;j++){
            merge_voting_result.set(j, merge_voting_result.get(j).multiply(val.get(j)).mod(paillier.nsquare));
        }
        return voting_num;
    }
    public List<BigInteger> GetMergeVotingResult() {
        return merge_voting_result;
    }
    public List<BigInteger> Encryption(List<BigInteger> val) {
        List<BigInteger> result = new ArrayList<>();
        for (int i = 0;i < val.size();i++) {
            result.add(paillier.Encryption(val.get(i)));
        }
        return result;
    }
    public List<BigInteger> Decryption(List<BigInteger> val) {
        List<BigInteger> result = new ArrayList<>();
        if (decryption) {
            for (int i = 0;i < val.size();i++) {
                result.add(paillier.Decryption(val.get(i)));
            }
        }
        return result;
    }
}
