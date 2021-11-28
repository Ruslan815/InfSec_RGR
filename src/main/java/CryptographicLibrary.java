import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ThreadLocalRandom;

public class CryptographicLibrary {
    /**
     * a^x mod p = y
     * Find: y
     * Input: a, x, p
     * Returns: long Y
     */
    public static long fastExponentiationModulo(long a, long x, long p) {
        if (x < 0) {
            a = CryptographicLibrary.generalizedEuclidAlgorithm(p, a)[2]; // find inverse of a
            if (a < 0) a += p;
            x *= -1;
        }

        int n = log2(x) + 1; // count of iterations

        String binaryString = Long.toString(x, 2); // приводим число в двоичную форму
        int[] binaryArr = new int[n];
        for (int i = 0; i < binaryArr.length; i++) {
            binaryArr[i] = Integer.parseInt(binaryString.substring(n - i - 1, n - i)); // записываем в массив в обратном порядке
        }

        long s = a;
        long answer = 1;
        for (int i = 0; i < n; i++) { // в цикле прохидимся по алгоритму
            if (binaryArr[i] == 1) {
                answer = answer * s % p; // сразу же перемножаем числа для ответа
            }
            s = s * s % p;
        }
        return answer;
    }

    private static int log2(long x) {
        return (int) (Math.log(x) / Math.log(2));
    }

    /**
     * ax + by = gcd(a, b)
     * Find: gcd(a, b), x, y
     * Input: a, b
     * Returns: long[] {gcd(a, b), x, y}
     */
    public static long[] generalizedEuclidAlgorithm(long a, long b) {
        long[] arrU = {a, 1, 0};
        long[] arrV = {b, 0, 1};
        long[] arrBuffer = new long[3];
        long q;

        while (arrV[0] != 0) {
            q = arrU[0] / arrV[0];
            //System.out.println("q: " + q);
            arrBuffer[0] = arrU[0] % arrV[0];
            arrBuffer[1] = arrU[1] - q * arrV[1];
            arrBuffer[2] = arrU[2] - q * arrV[2];
            arrU = Arrays.copyOf(arrV, arrV.length);
            arrV = Arrays.copyOf(arrBuffer, arrBuffer.length);
            //System.out.println(Arrays.toString(arrU));
            //System.out.println(Arrays.toString(arrV));
            //System.out.println();
        }
        //System.out.println("Answer is: " + arrU[0] + "\nx = " + arrU[1] + "\ny = " + arrU[2]);
        return arrU;
    }

    /**
     * Diffie-Hellman
     */
    public static void diffieHellman() {
        long[] arr = generateGeneralData();
        long P = arr[0]; // Безопасное простое число
        long g = arr[1]; // Первообразный корень по модулю P

        long privateKeyXa = 1 + (long) (Math.random() * (P - 1));
        long privateKeyXb = 1 + (long) (Math.random() * (P - 1)); // 1 <= X < p
        long publicKeyYa = fastExponentiationModulo(g, privateKeyXa, P);
        long publicKeyYb = fastExponentiationModulo(g, privateKeyXb, P);

        long sharedSecretKeyZab = fastExponentiationModulo(publicKeyYb, privateKeyXa, P);
        long sharedSecretKeyZba = fastExponentiationModulo(publicKeyYa, privateKeyXb, P);
        if (sharedSecretKeyZab != sharedSecretKeyZba) {
            System.err.println("Error in calculation");
        }

        System.out.println("Answer: " + sharedSecretKeyZab);
    }

    /**
     * Returns: int[] {P, g}
     */
    public static long[] generateGeneralData() {
        // Specify min value of Q
        long Q = ThreadLocalRandom.current().
                nextLong(Integer.MAX_VALUE >> 16, Integer.MAX_VALUE >> 2); // Q - Prime
        long P; // P = 2Q + 1
        // Specify min value of g
        long g = ThreadLocalRandom.current().
                nextLong(Integer.MAX_VALUE >> 22, Integer.MAX_VALUE >> 20); // (2 < g < P − 1) && (g^Q mod P != 1)

        boolean isPrimeP = false;
        while (!isPrimeP) {
            isPrimeP = isPrime(2L * Q + 1);
            if (!isPrimeP) {
                boolean isPrimeQ = isPrime(++Q);
                while (!isPrimeQ) {
                    isPrimeQ = isPrime(++Q);
                }
            }
        }
        P = 2L * Q + 1;
        //System.out.println("P && Q = " + P + ", " + Q);

        while (g < P - 1) {
            if (fastExponentiationModulo(g, Q, P) != 1) {
                break;
            }
            g++;
        }
        if (g == P - 1) {
            System.err.println("Exceptional situation!!!");
        }
        //System.out.println("g = " + g);

        return new long[]{P, g};
    }

    public static boolean isPrime(long number) {
        BigInteger bigInt = BigInteger.valueOf(number);
        return bigInt.isProbablePrime(100);
    }

    /**
     * a^x mod p = y
     * Find x
     * Input: a, p, y
     * Returns: long x
     */
    public static long babyStepGiantStep(long a, long p, long y) {
        int m = (int) Math.sqrt(p) + 1; // mk > p
        int k = m; // Можно оставить только переменную М для оптимизации
        if ((long) m * k <= p) {
            System.err.println("Need another mk!");
        }

        // (a^j * y) mod p
        // 0 <= j <= m - 1
        long[] rowM = new long[m];
        for (int j = 0; j < m; j++) {
            rowM[j] = ((long) Math.pow(a, j) * y) % p;
        }

        // a^im mod p
        // 1 <= i <= k
        long[] rowK = new long[k];
        for (int i = 1; i <= k; i++) {
            rowK[i - 1] = fastExponentiationModulo(a, (long) i * m, p);
        }

        // Ищем одинаковые элементы
        // a^im = a^j * y
        long answer = -1;
        Map<Long, Integer> mapM = new TreeMap<>();
        for (int j = 0; j < m; j++) {
            mapM.put(rowM[j], j); // rowM starts with (a^0 * y), rowK starts with (a^1m)
        }
        // 0 <= j < m
        // 1 <= i <= k
        for (int i = 0; i < k; i++) {
            if (mapM.containsKey(rowK[i])) {
                answer = (i + 1L) * m - mapM.get(rowK[i]); // x = i * m - j
                //System.out.println("j: " + mapM.get(rowK[i]) + ", i: " + (i + 1));
                break;
            }
        }

        //Answer: x = i * m - j
        if (answer == -1) {
            System.err.println("Cannot find a answer!");
        }
        //System.out.println("Answer: " + answer);
        return answer;
    }

    public static void main(String[] args) {
        System.out.println("fastExponentiationModulo: " + fastExponentiationModulo(5, 20, 7));
        System.out.println("generalizedEuclidAlgorithm: " + Arrays.toString(generalizedEuclidAlgorithm(28, 19)));
        diffieHellman();
        System.out.println("babyStepGiantStep: " + babyStepGiantStep(5, 7, 4));
    }
}
