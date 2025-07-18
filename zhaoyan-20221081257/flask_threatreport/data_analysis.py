import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import matplotlib as mpl
import platform


# 设置中文字体支持
def set_chinese_font():
    #配置 matplotlib 使用中文字体
    system = platform.system()

    if system == 'Windows':
        # Windows 系统使用 SimHei 字体
        plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'KaiTi', 'Arial Unicode MS']
    elif system == 'Darwin':
        # Mac 系统使用 AppleGothic 或 PingFang SC
        plt.rcParams['font.sans-serif'] = ['AppleGothic', 'PingFang SC', 'Heiti SC']
    else:
        # Linux 系统使用 WenQuanYi Micro Hei
        plt.rcParams['font.sans-serif'] = ['WenQuanYi Micro Hei', 'Noto Sans CJK SC']

    # 确保负号正常显示
    plt.rcParams['axes.unicode_minus'] = False


# 调用字体设置
set_chinese_font()



def analyze_threat_data(df):
    #执行数据分析并返回统计结果
    results = {}

    # 1. 威胁等级分布
    threat_level_dist = df['威胁等级值'].value_counts().sort_index()
    results['threat_level_dist'] = threat_level_dist.to_dict()

    # 2. TOP 威胁源
    top_sources = df['源IP'].value_counts().head(10)
    results['top_sources'] = top_sources.to_dict()

    # 3. 协议风险分析
    protocol_risk = df.groupby('应用层协议')['威胁等级值'].mean().sort_values(ascending=False)
    results['protocol_risk'] = protocol_risk.to_dict()

    # 4. 小时事件趋势
    df['小时'] = df['发现时间'].dt.hour
    hourly_trend = df.groupby('小时').size()
    results['hourly_trend'] = hourly_trend.to_dict()

    return results


def plot_threat_level_distribution(df):
    #生成威胁等级分布饼图
    threat_level_dist = df['威胁等级值'].value_counts().sort_index()
    threat_level_dist.index = [f'等级 {i}' for i in threat_level_dist.index]

    fig, ax = plt.subplots(figsize=(8, 6))
    colors = ['#FF6B6B', '#FF9E6D', '#FFD166', '#A0E8AF', '#4ECDC4']
    wedges, texts, autotexts = ax.pie(
        threat_level_dist,
        labels=threat_level_dist.index,
        autopct='%1.1f%%',
        startangle=90,
        colors=colors,
        wedgeprops={'edgecolor': 'white', 'linewidth': 1}
    )

    # 设置文字属性
    plt.setp(autotexts, size=10, weight="bold", color='white')
    plt.setp(texts, size=10)

    ax.set_title('威胁等级分布', fontsize=14, fontweight='bold')
    plt.tight_layout()
    return fig


def plot_top_threat_sources(df):
    """生成TOP威胁源柱状图"""
    top_sources = df['源IP'].value_counts().head(10)

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(
        top_sources.index,
        top_sources.values,
        color='#36A2EB'
    )

    # 添加数据标签
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

    ax.set_title('TOP 10 威胁源IP', fontsize=14, fontweight='bold')
    ax.set_xlabel('源IP地址', fontsize=10)
    ax.set_ylabel('事件数量', fontsize=10)
    plt.xticks(rotation=45, ha='right', fontsize=9)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    return fig


def plot_protocol_risk(df):
    #生成协议风险条形图
    protocol_risk = df.groupby('应用层协议')['威胁等级值'].mean().sort_values(ascending=False)

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(
        protocol_risk.index,
        protocol_risk.values,
        color='#FFCE56'
    )

    # 添加数据标签
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{width:.2f}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(3, 0),  # 3 points horizontal offset
                    textcoords="offset points",
                    ha='left', va='center')

    ax.set_title('应用层协议风险分析', fontsize=14, fontweight='bold')
    ax.set_xlabel('平均威胁等级', fontsize=10)
    ax.set_ylabel('应用层协议', fontsize=10)
    plt.grid(axis='x', linestyle='--', alpha=0.7)
    plt.tight_layout()
    return fig


def plot_hourly_trend(df):
    #生成小时事件趋势图
    if '小时' not in df.columns:
        df['小时'] = df['发现时间'].dt.hour

    hourly_trend = df.groupby('小时').size()

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(
        hourly_trend.index,
        hourly_trend.values,
        marker='o',
        color='#4BC0C0',
        linestyle='-',
        linewidth=2
    )

    # 填充曲线下方区域
    ax.fill_between(
        hourly_trend.index,
        hourly_trend.values,
        color='#4BC0C0',
        alpha=0.2
    )

    # 添加数据标签
    for x, y in zip(hourly_trend.index, hourly_trend.values):
        ax.annotate(f'{y}',
                    xy=(x, y),
                    xytext=(0, 5),
                    textcoords="offset points",
                    ha='center')

    ax.set_title('每小时事件数量趋势', fontsize=14, fontweight='bold')
    ax.set_xlabel('小时', fontsize=10)
    ax.set_ylabel('事件数量', fontsize=10)
    ax.set_xticks(range(0, 24))
    ax.set_xticklabels([f'{h:02d}:00' for h in range(0, 24)])
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    return fig


def get_critical_events(df):
    """获取高危事件列表（威胁等级值小于等于2）"""
    critical_events = df[df['威胁等级值'] <= 2].copy()

    if critical_events.empty:
        return []

    # 选择需要的列
    critical_events = critical_events[[
        '发现时间', '源IP', '目的IP', '应用层协议',
        '威胁名称', '威胁等级值', '详细信息'
    ]]

    # 格式化时间
    critical_events['发现时间'] = critical_events['发现时间'].dt.strftime('%Y-%m-%d %H:%M')

    # 限制详细信息长度
    critical_events['详细信息'] = critical_events['详细信息'].apply(
        lambda x: (x[:100] + '...') if len(x) > 100 else x
    )

    return critical_events.to_dict('records')