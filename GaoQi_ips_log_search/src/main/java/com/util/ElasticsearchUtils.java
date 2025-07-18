package com.util;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.slf4j.Logger;

/**
 * 配置类，用以生成连接 Elasticsearch 索引的 RestHighLevelClient 实例
 *
 * @author 张博
 * @date 2024-03-13
 */
public class ElasticsearchUtils {
    /**
     * 读写ES索引的高阶客户端
     */
    private RestHighLevelClient client = null;

    /**
     * @param hosts    配置文件中 es.hosts 的值
     * @param username 配置文件中 es.username 的值
     * @param password 配置文件中 es.password 的值
     */
    public RestHighLevelClient getClient(String hosts, String username, String password, Logger log) {
        if (client == null) {
            try {
                connect(hosts, username, password);
            } catch (Exception e) {
                log.error("创建es连接出现异常，程序终止，错误信息为：", e);
            }
        }
        return client;
    }

    private void connect(String hosts, String username, String password) throws Exception {
        String[] hostsArr = hosts.split(",");
        HttpHost[] httpHosts = new HttpHost[hostsArr.length];
        for (int i = 0; i < hostsArr.length; i++) {
            String[] hostInfo = hostsArr[i].split(":");
            httpHosts[i] = new HttpHost(hostInfo[0], Integer.parseInt(hostInfo[1]));
        }

        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));

        RestClientBuilder builder = RestClient.builder(httpHosts)
                .setHttpClientConfigCallback(
                        httpClientBuilder -> httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider)
                ).setRequestConfigCallback(
                        requestConfigBuilder -> requestConfigBuilder.setSocketTimeout(200000)
                );

        client = new RestHighLevelClient(builder);
    }

}
