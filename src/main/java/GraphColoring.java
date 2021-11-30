import java.io.*;
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

    private static int[] sequenceOfBobChecking;

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

    private static void fillArrayByIndexes(int[] arr) {
        for (int i = 0; i < arr.length; i++) {
            arr[i] = i;
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

    private static void generateR(long N) {
        r = new long[V];
        for (int i = 0; i < V; i++) {
            r[i] = ThreadLocalRandom.current().nextLong(0, N);
            int number = 0;
            switch (colors[i]) {
                case "B" -> number = 1;
                case "Y" -> number = 2;
            }
            r[i] = ((r[i] >> 2) << 2) | number;
            //System.out.println("R: " + colors[i] + " : " + Long.toBinaryString(r[i]));
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

            // Step 2
            generateR(N);
            // Step 2

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

            // Step 4
            GraphColoring.Z[i] = CryptographicLibrary.fastExponentiationModulo(GraphColoring.r[i], d, N);

            /*System.out.println("P : " + P);
            System.out.println("Q : " + Q);
            System.out.println("N : " + N);
            System.out.println("C : " + c);
            System.out.println("D : " + d);
            System.out.println("r: " + r[i]);
            System.out.println("Z1: " + Z[i]);
            long Z2 = CryptographicLibrary.fastExponentiationModulo(Z[i], c, N);
            System.out.println("Z2: " + Z2);
            System.out.println();*/
        }
    }

    private static boolean verifyEdge(int edgeNumber) {
        int firstVertexNumber = graph[edgeNumber][0];
        int secondVertexNumber = graph[edgeNumber][1];
        long firstC = C[firstVertexNumber];
        long secondC = C[secondVertexNumber];
        long firstZ = CryptographicLibrary.fastExponentiationModulo(Z[firstVertexNumber], firstC, N[firstVertexNumber]);
        long secondZ = CryptographicLibrary.fastExponentiationModulo(Z[secondVertexNumber], secondC, N[secondVertexNumber]);

        long firstNumber = firstZ & 3;
        long secondNumber = secondZ & 3;

        System.out.println("Edge #" + edgeNumber);
        System.out.println("Vertexes numbers: " + firstVertexNumber + " " + secondVertexNumber);
        System.out.println("Calculated Rs: " + firstZ + " " + secondZ);
        System.out.println("Calculated first 2 bits: " + firstNumber + " " + secondNumber);

        if (firstNumber == secondNumber) {
            System.err.println("Алиса тебя обманывает!");
            return false;
        }
        System.out.println("Успех.\n");
        return true;
    }

    private static void generateGraphColoring(int vertexes, String filename) throws IOException {
        if ((vertexes - 1) % 3 == 0) {
            System.err.println("Количество вершин V != 3n + 1, где n>=1.");
            throw new IllegalArgumentException();
        }

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(vertexes).append(" ").append(vertexes).append(System.lineSeparator()); // first string
        for (int i = 0; i < vertexes - 1; i++) {
            stringBuilder.append(i).append(" ").append(i + 1).append(System.lineSeparator());
        }
        stringBuilder.append(vertexes - 1).append(" ").append(0).append(System.lineSeparator());

        for (int i = 0; i < vertexes - 1; i++) {
            String currentColor = "R,";
            switch (i % 3) {
                case 1 -> currentColor = "B,";
                case 2 -> currentColor = "Y,";
            }
            stringBuilder.append(currentColor);
        }

        String currentColor = "R";
        switch ((vertexes - 1) % 3) {
            case 1 -> currentColor = "B";
            case 2 -> currentColor = "Y";
        }
        stringBuilder.append(currentColor);
        //System.out.println(stringBuilder);

        // Записываем граф в файл
        BufferedWriter writer = new BufferedWriter(new FileWriter(filename));
        writer.write(stringBuilder.toString());
        writer.close();
    }

    public static void main(String[] args) throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        int countOfVertexes = 0;
        String filename = "";

        while (true) {
            System.out.print("Введите количество вершин V в графе (V != 3n + 1, где n>=1): ");
            countOfVertexes = Integer.parseInt(bufferedReader.readLine());

            System.out.print("Введите имя файла для сохранения раскраски графа: ");
            filename = bufferedReader.readLine();
            generateGraphColoring(countOfVertexes, filename);
            readGraphFromFile(filename); //readGraphFromFile("Solution.txt");

            System.out.print("\nВведите число а (кол-во итераций): ");
            int countOfIterations = Integer.parseInt(bufferedReader.readLine());
            for (int i = 0; i < countOfIterations; i++) {
                System.out.println("****************");
                System.out.println("* Итерация #" + i + " *");
                System.out.println("****************");

                // Рандомим последовательность проверки рёбер
                // sequenceOfBobChecking = new int[E];
                // fillArrayByIndexes(sequenceOfBobChecking);
                // shuffleArray(sequenceOfBobChecking);

                // Проверяем рёбра
                //for (int k : sequenceOfBobChecking) {
                // Step 1
                fillArrayByIndexes(shuffleArray);
                shuffleArray(shuffleArray);
                shuffleGraphColors();

                // Step 3, 2, 4
                generateDataRSA();

                // Step 5
                int k = ThreadLocalRandom.current().nextInt(0, E);
                if (!verifyEdge(k)) {
                    return;
                }
                //}
            }

            System.out.println("Выйти из программы? (y/n): ");
            if (bufferedReader.readLine().equals("y")) break;
        }

        System.out.println("********************************");
        System.out.println("* Завершение работы программы. *");
        System.out.println("********************************");
        bufferedReader.close();
    }
}
