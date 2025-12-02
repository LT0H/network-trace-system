package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import swing.common.SwingUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static cic.cs.unb.ca.Sys.FILE_SEP;

public class Cmd {

    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";

    public static void main(String[] args) {
        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;
        
        // 简化命令行参数处理，只需要输入文件和输出目录
        if (args.length < 2) {
            logger.info("用法: java -jar cicflowmeter.jar <pcap文件路径> <输出目录>");
            return;
        }
        
        String pcapPath = args[0];
        String outPath = args[1];
        
        File inFile = new File(pcapPath);
        if (!inFile.exists() || !inFile.isFile()) {
            logger.error("PCAP文件不存在: {}", pcapPath);
            return;
        }
        
        File outDir = new File(outPath);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }
        
        if (!SwingUtils.isPcapFile(inFile)) {
            logger.error("请提供有效的PCAP文件");
            return;
        }
        
        logger.info("处理PCAP文件: {}", pcapPath);
        logger.info("输出目录: {}", outPath);
        
        // 确保输出文件名与输入文件一致，便于关联
        String fileName = FilenameUtils.getBaseName(pcapPath);
        processPcapFile(pcapPath, outPath, fileName, flowTimeout, activityTimeout);
    }

    private static void processPcapFile(String inputFile, String outPath, String baseFileName, 
                                       long flowTimeout, long activityTimeout) {
        if(inputFile == null || outPath == null || baseFileName == null) {
            return;
        }

        if(!outPath.endsWith(FILE_SEP)){
            outPath += FILE_SEP;
        }

        // 使用与PCAP文件相同的基础名称作为输出CSV文件
        String outputFileName = baseFileName + "_ISCX.csv";
        File saveFileFullPath = new File(outPath + outputFileName);

        // 如果文件已存在则删除
        if (saveFileFullPath.exists() && !saveFileFullPath.delete()) {
            logger.error("无法删除已存在的输出文件: {}", saveFileFullPath);
            return;
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(baseFileName, outPath, outputFileName));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

        logger.info("正在处理... {}", baseFileName);

        int nValid = 0;
        int nTotal = 0;
        int nDiscarded = 0;
        long start = System.currentTimeMillis();
        
        try {
            while(true) {
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if(basicPacket != null) {
                    flowGen.addPacket(basicPacket);
                    nValid++;
                } else {
                    nDiscarded++;
                }
            }
        } catch(PcapClosedException e) {
            // 正常结束
        } finally {
            // 处理剩余的流
            flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());
        }

        long lines = SwingUtils.countLines(saveFileFullPath.getPath());
        long end = System.currentTimeMillis();

        logger.info("处理完成! 耗时 {} 秒", ((end - start) / 1000));
        logger.info("生成 {} 个流记录", lines);
        logger.info("数据包统计: 总计={}, 有效={}, 丢弃={}", nTotal, nValid, nDiscarded);
        logger.info(DividingLine);
    }

    static class FlowListener implements FlowGenListener {

        private String fileName;
        private String outPath;
        private String outputFileName;
        private long cnt;

        public FlowListener(String fileName, String outPath, String outputFileName) {
            this.fileName = fileName;
            this.outPath = outPath;
            this.outputFileName = outputFileName;
            this.cnt = 0;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {
            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            InsertCsvRow.insert(FlowFeature.getHeader(), flowStringList, outPath, outputFileName);

            cnt++;
            logger.info("{} 已生成 {} 个流\r", fileName, cnt);
        }
    }
}