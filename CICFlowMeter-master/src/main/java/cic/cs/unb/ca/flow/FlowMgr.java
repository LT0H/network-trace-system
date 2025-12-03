package cic.cs.unb.ca.flow;

import java.io.File;

public class FlowMgr {
    // 移除 slf4j 日志依赖，用 System.out 替代（不影响功能）
    // protected static final Logger logger = LoggerFactory.getLogger(FlowMgr.class);

    private static String dataDir;

    static {
        init();
    }

    private static void init() {
        // 移除 Sys 类依赖，用 System.getProperty 获取系统路径分隔符
        String FILE_SEP = File.separator;
        String userHome = System.getProperty("user.home");
        StringBuilder sb = new StringBuilder();
        sb.append(userHome).append(FILE_SEP);
        sb.append("CICFlowMeter").append(FILE_SEP);
        sb.append("data").append(FILE_SEP);
        dataDir = sb.toString();

        File dir = new File(dataDir);
        if (!dir.exists()) {
            // 移除日志，用打印语句替代
            System.out.println("创建数据目录: " + dataDir);
            dir.mkdirs();
        }
    }

    public static String getDataDir() {
        return dataDir;
    }

    public static String getDailyDir() {
        String FILE_SEP = File.separator;
        StringBuilder sb = new StringBuilder(dataDir);
        sb.append("daily").append(FILE_SEP);
        return sb.toString();
    }
}