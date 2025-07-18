import pandas as pd
import numpy as np
import re
from datetime import datetime
import pytz
import matplotlib.pyplot as plt
import matplotlib as mpl
from matplotlib.font_manager import FontProperties


# 设置中文字体支持
def set_chinese_font():
    """设置中文字体支持"""
    try:
        # 尝试使用系统自带的中文字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'KaiTi', 'Arial Unicode MS']
        plt.rcParams['axes.unicode_minus'] = False  # 正确显示负号

        # 创建字体属性对象用于后续使用
        return FontProperties(fname=r'C:\Windows\Fonts\simhei.ttf')
    except:
        print("警告: 未能加载中文字体，图表可能无法正常显示中文")
        return None


def clean_and_analyze_ips_data(file_path):
    """
    执行IPS数据清洗与统计分析
    :param file_path: 附件2的XLSX文件路径
    :return: 清洗后的DataFrame和统计结果字典
    """
    # 设置中文字体
    chinese_font = set_chinese_font()

    # ==================== 1. 数据加载 ====================
    print("步骤1: 加载Excel数据...")
    try:
        # 读取Excel文件，指定日期列为'发现时间'
        df = pd.read_excel(
            file_path,
            parse_dates=['发现时间'],
            dtype={
                '事件ID': 'str',
                '源IP': 'str',
                '源端口': 'int',
                '目的IP': 'str',
                '目的端口': 'int',
                '应用层协议': 'category',
                '威胁类别': 'category',
                '威胁名称': 'category',
                '威胁等级': 'str',
                '详细信息': 'str'
            }
        )
        print(f"成功加载数据，共 {len(df)} 条记录")
    except Exception as e:
        print(f"数据加载失败: {str(e)}")
        return None, None

    # ==================== 2. 数据清洗 ====================
    print("\n步骤2: 数据清洗...")

    # 2.1 处理缺失值
    print("  - 处理缺失值...")
    df.fillna({
        '源端口': 0,
        '目的端口': 0,
        '威胁等级': 'severity_0',
        '详细信息': '无'
    }, inplace=True)

    # 2.2 提取威胁等级数值
    print("  - 提取威胁等级数值...")
    # 使用正则提取severity_后的数字
    df['威胁等级值'] = df['威胁等级'].str.extract(r'severity_(\d)').astype(int)

    # 2.3 标准化威胁类别
    print("  - 标准化威胁类别...")
    threat_category_map = {
        'tor-network-traffic': '匿名代理',
        'weird-behavior': '异常行为',
        'malware': '恶意软件',
        'exploit': '漏洞利用',
        'phishing': '网络钓鱼'
    }
    df['威胁类别'] = df['威胁类别'].map(threat_category_map).fillna('其他')

    # 2.4 时间处理与时区转换
    print("  - 处理时间数据...")
    # 确保时间列为datetime类型
    if not pd.api.types.is_datetime64_any_dtype(df['发现时间']):
        df['发现时间'] = pd.to_datetime(df['发现时间'], errors='coerce')

    # 转换时区为东八区
    #df['发现时间'] = df['发现时间'].dt.tz_localize('UTC').dt.tz_convert('Asia/Shanghai')

    # 提取时间特征
    df['日期'] = df['发现时间'].dt.date
    df['小时'] = df['发现时间'].dt.hour
    df['星期'] = df['发现时间'].dt.day_name()

    # 2.5 从详细信息提取IOC指标
    print("  - 提取IOC指标...")

    def extract_ioc(detail):
        """从详细信息中提取IOC指标"""
        if not isinstance(detail, str):
            return None

        patterns = [
            r"IOC or JA3 Fingerprint: ([^;]+)",  # 匹配IOC指纹
            r"源IP: (\d+\.\d+\.\d+\.\d+)",  # 匹配IP地址
            r"域名: ([^\s;]+)"  # 匹配域名
        ]

        for pattern in patterns:
            match = re.search(pattern, detail)
            if match:
                return match.group(1)
        return None

    df['IOC'] = df['详细信息'].apply(extract_ioc)

    # 2.6 清理IP地址
    print("  - 清理IP地址数据...")
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    df['源IP'] = df['源IP'].apply(
        lambda x: re.search(ip_pattern, str(x)).group(0) if re.search(ip_pattern, str(x)) else '未知')
    df['目的IP'] = df['目的IP'].apply(
        lambda x: re.search(ip_pattern, str(x)).group(0) if re.search(ip_pattern, str(x)) else '未知')

    # ==================== 3. 数据分析与统计 ====================
    print("\n步骤3: 数据分析与统计...")

    stats = {}

    # 3.1 基础统计
    stats['总事件数'] = len(df)
    stats['起始时间'] = df['发现时间'].min()
    stats['结束时间'] = df['发现时间'].max()
    stats['唯一源IP数'] = df['源IP'].nunique()
    stats['唯一目的IP数'] = df['目的IP'].nunique()

    # 3.2 威胁等级分布
    threat_level_dist = df['威胁等级值'].value_counts().sort_index()
    threat_level_dist.index = [f'等级 {i}' for i in threat_level_dist.index]
    stats['威胁等级分布'] = threat_level_dist

    # 3.3 TOP 10 威胁源
    stats['TOP10威胁源IP'] = df['源IP'].value_counts().head(10)

    # 3.4 按协议分析
    stats['协议威胁分析'] = df.groupby('应用层协议').agg(
        事件数量=('事件ID', 'count'),
        平均威胁等级=('威胁等级值', 'mean'),
        最大威胁=('威胁等级值', 'min')  # 等级值越小威胁越大
    ).sort_values('最大威胁', ascending=True)

    # 3.5 时间模式分析
    hourly_trend = df.groupby('小时').size()
    hourly_trend.index = [f"{h:02d}:00-{h:02d}:59" for h in hourly_trend.index]
    stats['小时事件趋势'] = hourly_trend

    # 按星期分析（确保中文显示）
    weekday_names = {
        'Monday': '星期一',
        'Tuesday': '星期二',
        'Wednesday': '星期三',
        'Thursday': '星期四',
        'Friday': '星期五',
        'Saturday': '星期六',
        'Sunday': '星期日'
    }
    weekly_trend = df.groupby('星期').size().rename(index=weekday_names)
    stats['周事件趋势'] = weekly_trend

    # 3.6 高危事件分析 (威胁等级值≤2)
    critical_events = df[df['威胁等级值'] <= 2]
    stats['高危事件数'] = len(critical_events)
    stats['TOP高危威胁'] = critical_events['威胁名称'].value_counts().head(5)

    # ==================== 4. 可视化分析 ====================
    print("\n步骤4: 生成可视化图表...")

    # 4.1 威胁等级分布饼图
    plt.figure(figsize=(10, 6))
    threat_level_dist.plot.pie(
        autopct='%1.1f%%',
        startangle=90,
        colors=['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#c2c2f0']
    )
    plt.title('威胁等级分布', fontproperties=chinese_font)
    plt.ylabel('')
    plt.tight_layout()
    plt.savefig('threat_level_distribution.png', dpi=300, bbox_inches='tight')

    # 4.2 小时事件趋势图
    plt.figure(figsize=(12, 6))
    hourly_trend.plot(kind='bar', color='#1f77b4')
    plt.title('每小时事件数量趋势', fontproperties=chinese_font)
    plt.xlabel('时间段', fontproperties=chinese_font)
    plt.ylabel('事件数量', fontproperties=chinese_font)
    plt.xticks(rotation=45, fontproperties=chinese_font)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('hourly_trend.png', dpi=300, bbox_inches='tight')

    # 4.3 TOP威胁源柱状图
    plt.figure(figsize=(12, 6))
    stats['TOP10威胁源IP'].plot(kind='bar', color='#2ca02c')
    plt.title('TOP 10 威胁源IP', fontproperties=chinese_font)
    plt.xlabel('源IP地址', fontproperties=chinese_font)
    plt.ylabel('事件数量', fontproperties=chinese_font)
    plt.xticks(rotation=45, fontproperties=chinese_font)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('top_threat_sources.png', dpi=300, bbox_inches='tight')

    # 4.4 周事件趋势图
    plt.figure(figsize=(10, 6))
    stats['周事件趋势'].plot(kind='bar', color='#ff7f0e')
    plt.title('每周事件数量趋势', fontproperties=chinese_font)
    plt.xlabel('星期', fontproperties=chinese_font)
    plt.ylabel('事件数量', fontproperties=chinese_font)
    plt.xticks(rotation=0, fontproperties=chinese_font)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('weekly_trend.png', dpi=300, bbox_inches='tight')

    print("\n数据清洗与分析完成!")
    print("=" * 50)
    print("关键统计摘要:")
    print(f"- 总事件数: {stats['总事件数']}")
    print(f"- 威胁等级分布:\n{stats['威胁等级分布']}")
    print(f"- 高危事件数(等级≤2): {stats['高危事件数']}")
    print(f"- 时间段: {stats['起始时间']} 至 {stats['结束时间']}")
    print("=" * 50)

    # 返回清洗后的数据和统计结果
    return df, stats


# ==================== 执行主函数 ====================
if __name__ == "__main__":
    # 替换为实际的附件2文件路径
    FILE_PATH = "IPSdata.xlsx"

    cleaned_df, analysis_stats = clean_and_analyze_ips_data(FILE_PATH)

    # 可选：保存清洗后的数据
    if cleaned_df is not None:
        cleaned_df.to_excel("IPSdata_cleaned.xlsx", index=False)
        print("清洗后数据已保存到: 清洗后IPS数据.xlsx")

        # 保存统计摘要到文本文件
        with open("IPS数据统计摘要.txt", "w", encoding='utf-8') as f:
            f.write("IPS威胁数据统计分析报告\n")
            f.write("=" * 50 + "\n")
            f.write(f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"原始文件: {FILE_PATH}\n")
            f.write(f"总事件数: {analysis_stats['总事件数']}\n")
            f.write(f"时间范围: {analysis_stats['起始时间']} 至 {analysis_stats['结束时间']}\n\n")

            f.write("威胁等级分布:\n")
            f.write(str(analysis_stats['威胁等级分布']) + "\n\n")

            f.write("TOP 10 威胁源IP:\n")
            f.write(str(analysis_stats['TOP10威胁源IP']) + "\n\n")

            f.write("高危事件统计(威胁等级≤2):\n")
            f.write(f"数量: {analysis_stats['高危事件数']}\n")
            f.write("TOP 5 高危威胁类型:\n")
            f.write(str(analysis_stats['TOP高危威胁']) + "\n")

        print("统计摘要已保存到: IPS数据统计摘要.txt")