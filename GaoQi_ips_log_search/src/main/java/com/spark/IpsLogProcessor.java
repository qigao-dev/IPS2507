package com.spark;

import com.util.ElasticsearchUtils;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.elasticsearch.xcontent.XContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.apache.spark.sql.functions.*;

public class IpsLogProcessor {

    public static Logger log = LoggerFactory.getLogger("TargetReporter");

    private static final String ES_HOST = "10.1.62.192:9200";
    private static final String ES_USERNAME = "elastic";
    private static final String ES_PASSWORD = "ebank@123";
    private static final String ES_INDEX = "ips_logs";

    public static void main(String[] args) {
        //System.setProperty("hadoop.security.authentication", "simple");

        SparkSession spark = SparkSession.builder()
                .appName("IPS Log Processor")
                .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
                //.config("spark.hadoop.security.authentication", "simple")
                .master("local[*]")
                .getOrCreate();

        try {
            Dataset<Row> rawData = spark.read()
                    .option("header", "true")
                    .option("delimiter", ",")
                    .option("inferSchema", "true")
                    .option("timestampFormat", "yyyy-MM-dd HH:mm:ss")
                    .csv("C:\\file\\partTime\\ips_log_search\\ips_logs.csv");

            Dataset<Row> cleanedData = processRawData(rawData);
            writeToElasticsearchInBatches(spark, cleanedData);

            log.info("数据成功写入Elasticsearch");
        } catch (Exception e) {
            log.error("处理失败: ", e);
        } finally {
            spark.stop();
        }
    }

    private static Dataset<Row> processRawData(Dataset<Row> rawData) {
        return rawData
                .withColumn("details", regexp_replace(col("详细信息"), "[\\n\\r\\s]+", " "))
                .withColumn("sourcePort", col("源端口").cast("int"))
                .withColumn("destinationPort", col("目的端口").cast("int"))
                .withColumn("timestamp", to_timestamp(col("发现时间"), "yyyy-MM-dd HH:mm:ss"))
                .select(
                        col("事件ID").as("eventId"),
                        col("timestamp"),
                        col("源IP").as("sourceIp"),
                        col("sourcePort"),
                        col("目的IP").as("destinationIp"),
                        col("destinationPort"),
                        col("应用层协议").as("protocol"),
                        col("威胁类别").as("threatCategory"),
                        col("威胁名称").as("threatName"),
                        col("威胁等级").as("threatLevel"),
                        col("details")
                );
    }

    private static final int BATCH_SIZE = 500; // 减少批次大小
    private static final int MAX_RETRIES = 3; // 最大重试次数
    private static final long RETRY_DELAY_MS = 1000; // 重试延迟

    private static void writeToElasticsearchInBatches(SparkSession spark, Dataset<Row> data) {
        ObjectMapper mapper = new ObjectMapper();
        List<String> jsonData = data.toJSON().collectAsList();
        int totalRecords = jsonData.size();
        int batches = (int) Math.ceil((double) totalRecords / BATCH_SIZE);

        try (RestHighLevelClient client = createResilientClient()) {
            for (int i = 0; i < batches; i++) {
                int from = i * BATCH_SIZE;
                int to = Math.min((i + 1) * BATCH_SIZE, totalRecords);
                List<String> batch = jsonData.subList(from, to);

                boolean success = executeWithRetry(client, batch, mapper, i+1, batches);
                if (!success) {
                    log.error("批次 {}/{} 最终写入失败，跳过该批次", i+1, batches);
                }

                // 动态调整延迟
                throttleBatchProcessing(i, batches);
            }
        } catch (IOException e) {
            log.error("Elasticsearch客户端创建失败: ", e);
        }
    }

    private static RestHighLevelClient createResilientClient() {
        return new ElasticsearchUtils().getClient(ES_HOST, ES_USERNAME, ES_PASSWORD, log);
    }

    private static boolean executeWithRetry(RestHighLevelClient client,
                                            List<String> batch,
                                            ObjectMapper mapper,
                                            int batchNum,
                                            int totalBatches) {
        for (int retry = 0; retry < MAX_RETRIES; retry++) {
            BulkRequest bulkRequest = new BulkRequest();
            int successCount = 0;

            try {
                for (String json : batch) {
                    try {
                        Map<String, Object> record = mapper.readValue(json, Map.class);
                        String docId = record.containsKey("eventId") && record.get("eventId") != null
                                ? record.get("eventId").toString()
                                : UUID.randomUUID().toString();

                        bulkRequest.add(new IndexRequest(ES_INDEX)
                                .id(docId)
                                .source(record, XContentType.JSON));
                        successCount++;
                    } catch (Exception e) {
                        log.warn("记录解析失败 (将跳过): {}, 错误: {}", json, e.getMessage());
                    }
                }

                if (bulkRequest.numberOfActions() > 0) {
                    client.bulk(bulkRequest, RequestOptions.DEFAULT);
                    log.info("批次 {}/{} 写入成功 (重试 {}): {} 条记录",
                            batchNum, totalBatches, retry, successCount);
                    return true;
                }
            } catch (IOException e) {
                log.warn("批次 {}/{} 写入失败 (重试 {}/{}): {}",
                        batchNum, totalBatches, retry+1, MAX_RETRIES, e.getMessage());

                if (retry < MAX_RETRIES - 1) {
                    try {
                        Thread.sleep(RETRY_DELAY_MS * (retry + 1));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                }
            }
        }
        return false;
    }

    private static void throttleBatchProcessing(int currentBatch, int totalBatches) {
        try {
            // 动态调整延迟：开始时延迟较小，接近结束时延迟增大
            long delay = Math.min(1000, 200 + (800 * currentBatch / totalBatches));
            if (currentBatch < totalBatches - 1) {
                Thread.sleep(delay);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}