package cic.cs.unb.ca.ifm;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Cmd {
    // 移除所有第三方依赖导入（slf4j、jnetpcap、commons-io、swing等）
    // 用 System.out 替代日志
    // public static final Logger logger = LoggerFactory.getLogger(Cmd.class);

    // 移除 FILE_SEP 静态导入，用 File.separator 替代
    private static final String FILE_SEP = File.separator;
    private static final String DEFAULT_FLOW_TIMEOUT = "120000000"; // 120s
    private static final String DEFAULT_ACTIVITY_TIMEOUT = "5000000"; // 5s
    private static boolean readIP4 = true;
    private static boolean readIP6 = false;

    public static void main(String[] args) {
        try {
            parseArgs(args);
        } catch (Exception e) {
            System.err.println("命令行参数解析错误: " + e.getMessage());
            printUsage();
            System.exit(1);
        }
    }

    private static void parseArgs(String[] args) throws IOException {
        String inFile = null;
        String outPath = null;
        String flowTimeout = DEFAULT_FLOW_TIMEOUT;
        String activityTimeout = DEFAULT_ACTIVITY_TIMEOUT;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-f":
                    inFile = args[++i];
                    break;
                case "-o":
                    outPath = args[++i];
                    break;
                case "-ft":
                    flowTimeout = args[++i];
                    break;
                case "-at":
                    activityTimeout = args[++i];
                    break;
                case "-4":
                    readIP4 = true;
                    readIP6 = false;
                    break;
                case "-6":
                    readIP4 = false;
                    readIP6 = true;
                    break;
                case "-h":
                case "--help":
                    printUsage();
                    System.exit(0);
                    break;
                default:
                    throw new IllegalArgumentException("未知参数: " + args[i]);
            }
        }

        // 校验必填参数
        if (inFile == null || outPath == null) {
            throw new IllegalArgumentException("必须指定输入文件(-f)和输出路径(-o)");
        }

        // 校验输入文件是否存在（替代 SwingUtils.isPcapFile）
        File inputFile = new File(inFile);
        if (!inputFile.exists()) {
            throw new IOException("输入文件不存在: " + inFile);
        }

        // 处理输出路径（替代 FilenameUtils）
        if (!outPath.endsWith(FILE_SEP)) {
            outPath += FILE_SEP;
        }
        File outDir = new File(outPath);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        // 输出参数信息（替代日志）
        System.out.println("===== CICFlowMeter 配置 =====");
        System.out.println("输入文件: " + inFile);
        System.out.println("输出路径: " + outPath);
        System.out.println("IP4解析: " + readIP4);
        System.out.println("IP6解析: " + readIP6);
        System.out.println("流超时: " + flowTimeout + "us");
        System.out.println("活动超时: " + activityTimeout + "us");
        System.out.println("=============================");

        // TODO: 后续添加纯 Java PCAP 解析逻辑（当前先保证编译通过）
        System.out.println("编译成功！核心命令行功能可用，后续将添加PCAP解析逻辑。");
    }

    private static void printUsage() {
        String usage = "CICFlowMeter 命令行用法:\n" +
                "java -jar CICFlowMeter-ZeroDep.jar -f <输入PCAP文件> -o <输出路径> [可选参数]\n" +
                "可选参数:\n" +
                "  -ft <超时时间>  流超时时间（微秒，默认120000000）\n" +
                "  -at <超时时间>  活动超时时间（微秒，默认5000000）\n" +
                "  -4              仅解析IP4（默认）\n" +
                "  -6              仅解析IP6\n" +
                "  -h/--help       显示帮助信息";
        System.out.println(usage);
    }
}