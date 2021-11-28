import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class ElectronicSignature {
    public static void RSA(byte[] message) {
        long P = ThreadLocalRandom.current().
                nextLong(2 << 6, Integer.MAX_VALUE >> 17); // P is big prime number
        while (!CryptographicLibrary.isPrime(++P)) ;
        long Q = ThreadLocalRandom.current().
                nextLong(2 << 6, Integer.MAX_VALUE >> 17); // Q is big prime number
        while (!CryptographicLibrary.isPrime(++Q) || Q == P) ;

        long N = P * Q;
        long Fi = (P - 1) * (Q - 1);
        long d = ThreadLocalRandom.current().nextLong(11, Integer.MAX_VALUE >> 16);
        while (CryptographicLibrary.generalizedEuclidAlgorithm(++d, Fi)[0] != 1 && d < Fi) ;
        if (d == Fi) {
            System.err.println("Не получилось сгенерировать число d.");
            return;
        }
        long c = CryptographicLibrary.generalizedEuclidAlgorithm(Fi, d)[2]; // Инверсия cd mod Fi = 1
        if (c < 0) c += Fi;

        // PUBLIC: N, d
        // PUBLIC key: d
        // PRIVATE key: c

        // Alice

        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA3-256"); // returns 32 bytes array
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
        byte[] hA = digest.digest(message);
        int[] intHA = byteArrToIntArr(hA); // 1 < h < P
        //System.out.println("SIZE: " + hA.length);

        long[] s = new long[intHA.length];
        for (int i = 0; i < s.length; i++) {
            s[i] = CryptographicLibrary.fastExponentiationModulo(intHA[i], c, N);
        }
        //message[0] = 77;
        //return new RSAPair(message, s);

        // Alice -> Bob <m, s>

        System.out.println(Arrays.toString(s));
        writeByteArrayToFile("/Users/vadimgrebensikov/4 course/Information/Lab1/src/Signature1", toByte(s));
        byte[] newByteArray = fileToByteArray("/Users/vadimgrebensikov/4 course/Information/Lab1/src/Signature1");
        s = convertByteArrayToLongArray(newByteArray);
        System.out.println(Arrays.toString(s));

        // Bob

        byte[] hB = digest.digest(message);
        int[] intHB = byteArrToIntArr(hB); // 1 < h < P
        long[] e = new long[s.length];
        for (int i = 0; i < s.length; i++) {
            e[i] = CryptographicLibrary.fastExponentiationModulo(s[i], d, N);
        }

        for (int i = 0; i < s.length; i++) {
            if (e[i] != intHB[i]) {
                System.err.println("RSA: Invalid signature!");
                return;
            }
        }
        System.out.println("RSA: Valid signature.");
    }

    public static byte[] toByte(long[] longArray) {
        ByteBuffer bb = ByteBuffer.allocate(longArray.length * Long.BYTES);
        bb.asLongBuffer().put(longArray);
        return bb.array();
    }

    public static long[] convertByteArrayToLongArray(byte[] data) {
        if (data == null || data.length % Long.BYTES != 0) return null;
        long[] longs = new long[data.length / Long.BYTES];
        for (int i = 0; i < longs.length; i++)
            longs[i] = ( convertByteArrayToLong(new byte[] {
                    data[(i*Long.BYTES)],
                    data[(i*Long.BYTES)+1],
                    data[(i*Long.BYTES)+2],
                    data[(i*Long.BYTES)+3],
                    data[(i*Long.BYTES)+4],
                    data[(i*Long.BYTES)+5],
                    data[(i*Long.BYTES)+6],
                    data[(i*Long.BYTES)+7],
            } ));
        return longs;
    }

    private static long convertByteArrayToLong(byte[] longBytes){
        ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
        byteBuffer.put(longBytes);
        byteBuffer.flip();
        return byteBuffer.getLong();
    }

    public static int[] byteArrToIntArr(byte[] bArr) {
        int[] iArr = new int[bArr.length];
        for (int i = 0; i < iArr.length; i++) {
            iArr[i] = bArr[i] + 129;
        }
        return iArr;
    }

    public static byte[] fileToByteArray(String filename) {
        try {
            return Files.readAllBytes(Path.of(filename));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void writeByteArrayToFile(String filename, byte[] arr) {
        try {
            Files.write(Path.of(filename), arr);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void Elgamal(byte[] message) {
        long[] arr = CryptographicLibrary.generateGeneralData();
        long P = arr[0]; // Безопасное простое число
        long g = arr[1]; // Первообразный корень по модулю P
        long x = ThreadLocalRandom.current().nextLong(2, P - 1); // 1 < x < P - 1
        long y = CryptographicLibrary.fastExponentiationModulo(g, x, P);

        // PUBLIC: P, g, y

        // Alice

        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA3-256"); // returns 32 bytes array
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
        byte[] hA = digest.digest(message);
        int [] intHA = byteArrToIntArr(hA);
        long k = ThreadLocalRandom.current().nextLong(1, P / 4);
        while (CryptographicLibrary.generalizedEuclidAlgorithm(++k, P - 1)[0] != 1);
        if (k >= P - 1) {
            System.err.println("Elgamal: Не получилось сгенерировать число k.");
            return;
        }
        long r = CryptographicLibrary.fastExponentiationModulo(g, k, P);
        long[] u = new long[intHA.length];
        for (int i = 0; i < u.length; i++) {
            u[i] = (intHA[i] - x * r) % (P - 1);
        }

        long inverseK = CryptographicLibrary.generalizedEuclidAlgorithm(P - 1, k)[2]; // kk^-1 mod (P - 1) = 1
        long[] s = new long[u.length];
        for (int i = 0; i < s.length; i++) {
            s[i] = (inverseK * u[i]) % (P - 1);
        }

        // Alice -> Bob <m, r, s>
        long[] tempS = new long[s.length + 1];
        tempS[s.length] = r;
        System.arraycopy(s, 0, tempS, 0, s.length);
        System.out.println(Arrays.toString(tempS));
        writeByteArrayToFile("/Users/vadimgrebensikov/4 course/Information/Lab1/src/Signature2", toByte(tempS));
        byte[] newByteArray = fileToByteArray("/Users/vadimgrebensikov/4 course/Information/Lab1/src/Signature2");
        long[] newLongArray= convertByteArrayToLongArray(newByteArray);
        r = newLongArray[newLongArray.length - 1];
        System.arraycopy(newLongArray, 0, s, 0, s.length);
        System.out.println(Arrays.toString(newLongArray));

        byte[] hB = digest.digest(message);
        int[] intHB = byteArrToIntArr(hB);
        long[] leftArr = new long[s.length];
        for (int i = 0; i < leftArr.length; i++) {
            leftArr[i] = (CryptographicLibrary.fastExponentiationModulo(y, r, P) * CryptographicLibrary.fastExponentiationModulo(r, s[i], P)) % P;
        }

        long[] rightArr = new long[intHB.length];
        for (int i = 0; i < rightArr.length; i++) {
            rightArr[i] = CryptographicLibrary.fastExponentiationModulo(g, intHB[i], P);
        }

        for (int i = 0; i < intHB.length; i++) {
            if (leftArr[i] != rightArr[i]) {
                System.err.println("Elgamal: Invalid signature!");
                return;
            }
        }
        System.out.println("Elgamal: Valid signature.");
    }

    public static void GOST(byte[] message) {
        List<Long> listOfQ = new ArrayList<>();
        for (int i = (1 << 15); i < (1 << 16); i++) {
            if (CryptographicLibrary.isPrime(i)) {
                listOfQ.add((long) i);
            }
        }
        long Q = listOfQ.get(ThreadLocalRandom.current().nextInt(0, listOfQ.size())); // 16 bit

        List<Long> listOfP = new ArrayList<>();
        for (int i = (1 << 15); i < (1 << 16); i++) {
            long num = i * Q + 1;
            if (CryptographicLibrary.isPrime(num) && num >= (1L << 30) && num < (1L << 31)) {
                listOfP.add(num);
            }
        }
        long P = listOfP.get(ThreadLocalRandom.current().nextInt(0, listOfP.size())); // 31 bit // P = bQ + 1

        // System.out.println("Q & P: " + Q + " " + P);

        long b = (P - 1) / Q;
        long g = ThreadLocalRandom.current().nextLong(2, (P - 1) / 4);
        while (CryptographicLibrary.fastExponentiationModulo(++g, b, P) <= 1) ;
        long a = CryptographicLibrary.fastExponentiationModulo(g, b, P);
        if (CryptographicLibrary.fastExponentiationModulo(a, Q, P) != 1) {
            System.err.println("GOST: Не получилось сгенерировать параметр а!");
            return;
        }

        // Общие параметры: p, q, a
        // x - секретный ключ, у - открытый ключ

        long x = ThreadLocalRandom.current().nextLong(1, Q);
        long y = CryptographicLibrary.fastExponentiationModulo(a, x, P);

        // Algorithm
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA3-256"); // returns 32 bytes array
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
        byte[] hA = digest.digest(message);
        int [] intHA = byteArrToIntArr(hA);
        long r;
        long[] s = new long[intHA.length];
        while (true) {
            long k = ThreadLocalRandom.current().nextLong(1, Q);
            r = CryptographicLibrary.fastExponentiationModulo(a, k, P) % Q;
            if (r == 0) continue;
            boolean isValidS = true;
            for (int i = 0; i < s.length; i++) {
                s[i] = (k * intHA[i] + x * r) % Q;
                if (s[i] == 0) {
                    isValidS = false;
                    break;
                }
            }
            if (!isValidS) continue;
            break;
        }

        // message[0] = 1;
        // r = 5;
        // s[0] = 3;
        // <m, r, s>
        long[] tempS = new long[s.length + 1];
        tempS[s.length] = r;
        System.arraycopy(s, 0, tempS, 0, s.length);
        System.out.println(Arrays.toString(tempS));
        writeByteArrayToFile("/Users/vadimgrebensikov/4 course/Information/Lab1/src/Signature3", toByte(tempS));
        byte[] newByteArray = fileToByteArray("/Users/vadimgrebensikov/4 course/Information/Lab1/src/Signature3");
        long[] newLongArray= convertByteArrayToLongArray(newByteArray);
        r = newLongArray[newLongArray.length - 1];
        System.arraycopy(newLongArray, 0, s, 0, s.length);
        System.out.println(Arrays.toString(newLongArray));

        byte[] hB = digest.digest(message);
        int [] intHB = byteArrToIntArr(hB);

        if (r <= 0 || r >= Q) {
            System.err.println("GOST: Invalid r!");
            return;
        }
        for (int i = 0; i < s.length; i++) {
            if (s[i] <= 0 || s[i] >= Q) {
                System.err.println("GOST: Invalid s!");
                return;
            }
        }

        int[] inverseH = new int[intHB.length];
        for (int i = 0; i < inverseH.length; i++) {
            inverseH[i] = (int) CryptographicLibrary.fastExponentiationModulo(intHB[i], -1, Q); // Inverse throw Fast Exponentiation
        }

        long[] u1 = new long[intHB.length];
        long[] u2 = new long[intHB.length];
        for (int i = 0; i < intHB.length; i++) {
            u1[i] = (s[i] * inverseH[i]) % Q;
            u2[i] = (-r * inverseH[i]) % Q;
        }

        long[] v = new long[intHB.length];
        for (int i = 0; i < intHB.length; i++) {
            v[i] = ((CryptographicLibrary.fastExponentiationModulo(a, u1[i], P) * CryptographicLibrary.fastExponentiationModulo(y, u2[i], P)) % P) % Q;
        }

        for (int i = 0; i < intHB.length; i++) {
            if (v[i] != r) {
                System.err.println("GOST: Invalid signature!");
                return;
            }
        }
        System.out.println("GOST: Valid signature.");
    }

    public static void main(String[] args) {
        String inFileName = "/Users/vadimgrebensikov/4 course/Information/Lab1/src/Hello";
        String outFileName = "/Users/vadimgrebensikov/4 course/Information/Lab1/src/Hello2";
        byte[] fileInBytes = fileToByteArray(inFileName);
        ElectronicSignature.RSA(fileInBytes);
        Elgamal(fileInBytes);
        GOST(fileInBytes);
    }
}
