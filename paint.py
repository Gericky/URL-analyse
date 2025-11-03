
import matplotlib.pyplot as plt
from matplotlib import rcParams

# --- 中文支持配置 ---
config = {
    "font.family": 'sans-serif',
    "font.sans-serif": ['SimHei', 'PingFang SC', 'Hiragino Sans GB', 'Arial Unicode MS', 'DejaVu Sans'],
    "axes.unicode_minus": False  # 正常显示负号
}
rcParams.update(config)
# -------------------
sizes = [40.8, 59.2]  # 规则 vs 模型
labels = ['规则引擎 (40.8%)', '模型推理 (59.2%)']
colors = ['#66b3ff', '#ff9999']

fig, ax = plt.subplots(figsize=(7, 6))
ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors, textprops={'fontsize': 12})
ax.set_title('图3. 检测方法调用比例', fontsize=14, pad=20)
plt.savefig('pie_chart.png', dpi=300, bbox_inches='tight')
plt.show()