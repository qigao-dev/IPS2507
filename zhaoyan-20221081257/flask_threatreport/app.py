from flask import Flask, render_template
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import numpy as np
from datetime import datetime
import data_analysis  # 自定义数据分析模块

app = Flask(__name__)


def generate_base64_chart(plt_figure):
    #将 matplotlib 图表转换为 Base64 字符串
    buf = BytesIO()
    plt_figure.savefig(buf, format='png', dpi=100)
    plt.close(plt_figure)
    return base64.b64encode(buf.getvalue()).decode('utf-8')


@app.route('/')
def dashboard():
    #仪表盘页面 - 显示所有分析结果
    # 加载数据
    try:
        df = pd.read_excel('cleaned_data.xlsx')
    except Exception as e:
        return render_template('error.html', error=f"数据加载失败: {str(e)}")

    # 分析数据
    analysis_results = data_analysis.analyze_threat_data(df)

    # 生成图表
    charts = {
        'threat_level_dist': generate_base64_chart(
            data_analysis.plot_threat_level_distribution(df)
        ),
        'top_threat_sources': generate_base64_chart(
            data_analysis.plot_top_threat_sources(df)
        ),
        'protocol_risk': generate_base64_chart(
            data_analysis.plot_protocol_risk(df)
        ),
        'hourly_trend': generate_base64_chart(
            data_analysis.plot_hourly_trend(df)
        )
    }

    # 获取高危事件列表
    critical_events = data_analysis.get_critical_events(df)

    # 基本统计信息
    stats = {
        'total_events': len(df),
        'critical_count': len(critical_events),
        'start_time': df['发现时间'].min().strftime('%Y-%m-%d %H:%M') if not df.empty else 'N/A',
        'end_time': df['发现时间'].max().strftime('%Y-%m-%d %H:%M') if not df.empty else 'N/A',
        'top_source': df['源IP'].value_counts().idxmax() if not df.empty else 'N/A',
        'most_common_threat': df['威胁名称'].value_counts().idxmax() if not df.empty else 'N/A'
    }

    # 获取当前时间
    current_time = datetime.now()

    return render_template(
        'dashboard.html',
        charts=charts,
        critical_events=critical_events,
        stats=stats,
        now=current_time  # 添加 now 变量
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)