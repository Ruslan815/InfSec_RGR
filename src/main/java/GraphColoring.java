import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class GraphColoring {

    private static int V;
    private static int E;
    private static int[][] graph;
    private static String[] colors;
    private static int[] shuffleArray = {0, 1, 2}; // Red(0) Blue(1) Yellow(2)

    private static long[] r;
    private static long[] N; // Public
    private static long[] C; // Secret key
    private static long[] D; // Public key
    private static long[] Z; // Public

    private static void readGraphFromFile(String filename) throws FileNotFoundException {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));

            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            String everything = sb.toString();
            br.close();

            String[] fileLines = everything.split(System.lineSeparator());
            V = Integer.parseInt(fileLines[0].split(" ")[0]);
            E = Integer.parseInt(fileLines[0].split(" ")[1]);
            graph = new int[E][2];
            for (int i = 0; i < E; i++) {
                graph[i][0] = Integer.parseInt(fileLines[i + 1].split(" ")[0]);
                graph[i][1] = Integer.parseInt(fileLines[i + 1].split(" ")[1]);
            }
            colors = fileLines[fileLines.length - 1].split(",");
            /*System.out.println("V, E: " + V + ", " + E);
            for (int i = 0; i < graph.length; i++) {
                for (int j = 0; j < 2; j++) {
                    System.out.print(graph[i][j] + " ");
                }
                System.out.println();
            }
            System.out.println("Colors: " + Arrays.toString(colors));*/
        } catch (Exception exception) {
            System.err.println("Не удалось считать файл: " + filename);
            throw new FileNotFoundException();
        }
    }

    private static void shuffleArray(int[] arr) {
        Random rnd = ThreadLocalRandom.current();
        for (int i = arr.length - 1; i > 0; i--) {
            int index = rnd.nextInt(i + 1);
            int temp = arr[index];
            arr[index] = arr[i];
            arr[i] = temp;
        }
    }

    private static void shuffleGraphColors() {
        for (int i = 0; i < colors.length; i++) {
            String tempColor = colors[i];
            int index = 0;
            switch (tempColor) {
                case "B" -> index = 1;
                case "Y" -> index = 2;
            }
            switch (shuffleArray[index]) {
                case 0 -> tempColor = "R";
                case 1 -> tempColor = "B";
                case 2 -> tempColor = "Y";
            }
            colors[i] = tempColor;
        }
    }

    private static void generateR() {
        r = new long[V];
        for (int i = 0; i < V; i++) {
            r[i] = ThreadLocalRandom.current().nextLong(Integer.MAX_VALUE >> 16, Integer.MAX_VALUE >> 2);
            int number = 0;
            switch (colors[i]) {
                case "B" -> number = 1;
                case "Y" -> number = 2;
            }
            r[i] = ((r[i] >> 2) << 2) | number;
        }
    }

    private static void generateDataRSA() throws Exception {
        GraphColoring.N = new long[V];
        GraphColoring.C = new long[V];
        GraphColoring.D = new long[V];
        GraphColoring.Z = new long[V];

        for (int i = 0; i < V; i++) {
            long P = ThreadLocalRandom.current().nextLong(2 << 6, Integer.MAX_VALUE >> 17); // P is big prime number
            while (!CryptographicLibrary.isPrime(++P)) ;
            long Q = ThreadLocalRandom.current().nextLong(2 << 6, Integer.MAX_VALUE >> 17); // Q is big prime number
            while (!CryptographicLibrary.isPrime(++Q) || Q == P) ;

            long N = P * Q;
            long Fi = (P - 1) * (Q - 1);
            long d = ThreadLocalRandom.current().nextLong(11, Integer.MAX_VALUE >> 16);
            while (CryptographicLibrary.generalizedEuclidAlgorithm(++d, Fi)[0] != 1 && d < Fi) ;
            if (d == Fi) {
                System.err.println("Не получилось сгенерировать число d.");
                throw new Exception();
            }
            long c = CryptographicLibrary.generalizedEuclidAlgorithm(Fi, d)[2]; // Инверсия cd mod Fi = 1
            if (c < 0) c += Fi;

            GraphColoring.N[i] = N;
            GraphColoring.C[i] = c;
            GraphColoring.D[i] = d;
            GraphColoring.Z[i] = CryptographicLibrary.fastExponentiationModulo(GraphColoring.r[i], d, N);
        }
    }

    public static void main(String[] args) throws Exception {
        readGraphFromFile("Solution.txt");
        // Step 1
        shuffleArray(shuffleArray);
        shuffleGraphColors();

        // Step 2
        generateR();

        // Step 3, 4
        generateDataRSA();

        // Step 5
        int edgeNumber = ThreadLocalRandom.current().nextInt(0, E);
        int firstVertexNumber = graph[edgeNumber][0];
        int secondVertexNumber = graph[edgeNumber][1];
        long firstC = C[firstVertexNumber];
        long secondC = C[secondVertexNumber];
        long firstZ = CryptographicLibrary.fastExponentiationModulo(Z[firstVertexNumber], firstC, N[firstVertexNumber]);
        long secondZ = CryptographicLibrary.fastExponentiationModulo(Z[secondVertexNumber], secondC, N[secondVertexNumber]);

        long firstNumber = firstZ & 3;
        long secondNumber = secondZ & 3;
        if (firstNumber == secondNumber) {
            System.err.println("Граф не раскрашен!");
            return;
        }
        System.out.println("Раскраска совпала.");
        System.out.println(edgeNumber);
        System.out.println(firstVertexNumber + " " + secondVertexNumber);
        System.out.println(firstNumber + " " + secondNumber);
    }
}
