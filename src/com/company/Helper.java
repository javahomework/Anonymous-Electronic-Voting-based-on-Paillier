package com.company;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class Helper {
    public static byte[] IntToBytes(int integer)
    {
        byte[] bytes = new byte[4];
        bytes[3] = (byte)(integer >> 24);
        bytes[2] = (byte)(integer >> 16);
        bytes[1] = (byte)(integer >> 8);
        bytes[0] = (byte)(integer);
        return bytes;
    }
    public static int BytesToInt(byte[] bytes, int start)
    {
        int int1 = bytes[start] & 0xff;
        int int2 = (bytes[start + 1] & 0xff) << 8;
        int int3 = (bytes[start + 2] & 0xff) << 16;
        int int4 = (bytes[start + 3] & 0xff) << 24;
        return int1 | int2 | int3 | int4;
    }
    public static byte[] BigIntegetListToBytes(List<BigInteger> big_integer_list) {
        List<byte[]> results = new ArrayList<>();
        int count = 0;
        for (int i = 0;i < big_integer_list.size();i++) {
            byte[] res = big_integer_list.get(i).toByteArray();
            results.add(res);
            count += res.length + 4;
        }
        byte[] result = new byte[count];
        count = 0;
        for (int i = 0;i < big_integer_list.size();i++) {
            int size = results.get(i).length;
            System.arraycopy(IntToBytes(size), 0, result, count, 4);
            count += 4;
            System.arraycopy(results.get(i), 0, result, count, size);
            count += size;
        }
        return result;
    }
    public static List<BigInteger> BytesToBigIntegetList(byte[] bytes) {
        List<BigInteger> results = new ArrayList<>();
        int count = 0;
        while (count < bytes.length) {
            int size = BytesToInt(bytes, count);
            count += 4;
            byte[] res = new byte[size];
            System.arraycopy(bytes, count, res, 0, size);
            count += size;
            BigInteger result = new BigInteger(res);
            results.add(result);
        }
        return results;
    }
}
