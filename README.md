# 渊照 YuanZhao — 专业暗链扫描工具

渊照是一款命令行暗链扫描工具，用于检测网站、HTML 文件或目录中的隐蔽链接、隐藏元素和恶意代码。支持三种扫描模式、多线程并发、无头浏览器增强以及四种报告格式。

## 环境要求

- Python 3.10+

## 安装

```bash
# 克隆项目
git clone https://github.com/KaneTheo/YuanZhao.git
cd YuanZhao

# 安装核心依赖
pip install -e .

# 如需无头浏览器功能，安装可选依赖
pip install -e ".[headless]"

# 如需运行测试
pip install -e ".[dev]"
```

安装后可使用 `yuanzhao` 命令（全局可用）或 `python -m yuanzhao`。

## 快速开始

```bash
# 扫描单个 HTML 文件，输出纯文本报告
yuanzhao test.html

# 扫描网站，深度模式，生成 HTML 报告
yuanzhao https://example.com -m deep -f html --verbose

# 扫描目录（递归 2 层），标准模式，16 线程
yuanzhao ./website -d 2 -m standard -t 16

# 启用无头浏览器检测动态内容
yuanzhao https://example.com --headless --js-wait 5

# 批量扫描（目标列表文件，每行一个目标）
yuanzhao targets.txt -m deep -f html --verbose

# 查看所有参数
yuanzhao --help
```

## 扫描模式

| 模式 | 说明 |
|------|------|
| `fast` | 仅做基础检测：HTML 可疑 URL、关键词匹配 |
| `standard` | 增加 JS/CSS 检测、特殊隐藏手法检测 |
| `deep` | 在 standard 基础上启用全部检测项 |

## 报告格式

| 格式 | 适用场景 |
|------|----------|
| `txt` | 纯文本，适合快速查看 |
| `html` | 可视化报告，适合呈现给他人 |
| `json` | 结构化数据，适合程序处理或 CI/CD 集成 |
| `csv` | 表格数据，适合 Excel 导入分析 |

## 命令行参数

### 基本参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `target` | 扫描目标（文件路径、目录路径或 URL）| 必填 |
| `-d, --depth` | 目录递归深度 | 3 |
| `-m, --mode` | 扫描模式 (fast/standard/deep) | deep |
| `-t, --threads` | 并发线程数 (1-100) | 8 |

### 报告参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-o, --output` | 报告输出目录 | `./reports` |
| `-f, --format` | 报告格式 (txt/html/json/csv) | txt |

### 网络参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--timeout` | HTTP 请求超时（秒）| 30 |
| `--proxy` | HTTP 代理，如 `http://127.0.0.1:8080` | — |

### 文件过滤与自定义规则

| 参数 | 说明 |
|------|------|
| `--exclude` | 排除的文件/目录模式，支持多个，如 `--exclude "*.jpg" "node_modules/"` |
| `--keyword-file` | 自定义关键字 CSV 文件路径（默认使用内置关键字表）|
| `--rules-file` | 自定义检测规则 YAML 文件路径（支持扩展正则检测）|

### 无头浏览器

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--headless` | 启用 Chrome 无头浏览器扫描 | 关闭 |
| `--headless-binary` | Chrome 浏览器可执行文件路径 | 系统默认 |
| `--headless-driver` | ChromeDriver 路径 | 自动检测 |
| `--headless-timeout` | 无头浏览器超时（秒）| 60 |
| `--js-wait` | 页面 JS 执行等待时间（秒）| 3 |

### 其他

| 参数 | 说明 |
|------|------|
| `--target-file` | 批量目标列表文件（每行一个 URL/文件/目录路径）|
| `--verbose` | 输出详细日志 |
| `--no-color` | 禁用彩色输出 |
| `--version` | 显示版本号 |

## 自定义关键字

内置关键字文件位于 `yuanzhao/rules/keywords.csv`，包含 198 条关键字，覆盖博彩、色情、恶意软件、钓鱼等类别。

如需自定义，创建 CSV 文件（格式：`关键字,类别,权重`），通过 `--keyword-file` 指定：

```csv
custom_keyword,gambling,8
another_term,malware,9
```

- 类别可选值：`gambling`、`porn`、`malware`、`phishing`、`other`
- 权重范围：1-10（10 为最高风险）
- 支持 `#` 开头的注释行

## 自定义检测规则

通过 YAML 文件定义任意 Python 正则规则来扩展检测能力。使用 `--rules-file` 参数加载：

```bash
yuanzhao https://example.com --rules-file my_rules.yaml -m deep
```

规则文件格式（示例见 `yuanzhao/rules/custom_rules.example.yaml`）：

```yaml
rules:
  - rule_id: "custom:my_rule"       # 规则唯一标识
    pattern: 'https?://evil-\w+\.com'  # Python 正则表达式
    flags: "i"                      # 正则标志: i(忽略大小写) s(点匹配换行) m(多行)
    severity: 8                     # 严重程度 1-10
    category: "suspicious_url"      # 分类: suspicious_url/hidden_element/keyword_match/js_issue/css_issue/suspicious_pattern
    source_type: "html"             # 来源类型: html/js/css/text/comments/meta/dynamic
    description: "匹配可疑域名"      # 规则描述
```

支持的 category（对应报告分类）：
- `suspicious_url` — 可疑链接
- `hidden_element` — 隐藏元素
- `keyword_match` — 关键字匹配
- `js_issue` — JavaScript 问题
- `css_issue` — CSS 问题
- `suspicious_pattern` — 其他可疑模式

## 支持的检测项

### URL 检测
- JavaScript 伪协议（`javascript:`）
- Data URI
- 高风险域名后缀（`.xyz`、`.tk`、`.ml`、`.pro` 等）
- 短链接服务（`bit.ly`、`t.co` 等）
- 非标准端口
- 随机生成域名
- 可疑查询参数

### 隐藏元素检测（正则 + BS4 DOM 分析）

**DOM 结构分析（BeautifulSoup）**
- Script 标签：外部可疑域名、缺少 SRI 完整性校验、内联高危函数
- Iframe：外部来源、隐藏尺寸（0x0/1x1）、缺少 sandbox 属性
- 链接：隐藏链接（display:none/opacity:0/font-size:0/offscreen/aria-hidden）、可疑外部链接
- 表单：外部提交 action、隐藏敏感字段、HTTP 明文登录表单
- 隐藏 class 名称（hidden/hide/invisible/visually-hidden/sr-only/d-none）
- hidden 属性和 aria-hidden 检测

**正则匹配**
- `display: none` / `visibility: hidden`
- `opacity: 0` / `font-size: 0`
- 绝对定位出屏（`left: -9999px` 等）
- 文本负缩进隐藏
- 文字与背景同色
- 零宽字符隐藏
- HTML 实体编码隐藏
- 多层嵌套隐藏

### JavaScript 检测
- `eval`、`Function`、`setTimeout` 等高风险函数
- 十六进制/Unicode 编码混淆
- 字符串拼接、数组 join 混淆
- 自执行函数
- Cookie/UserAgent/Referrer 读取
- DOM 操作（innerHTML、appendChild 等）
- 信息熵分析

### CSS 检测
- 异常长的选择器名称
- 外部 `@import` 引入
- CSS 注释中的敏感关键词
- Data URI / JavaScript URL
- 控制字符检测

## 项目结构

```
YuanZhao/
├── .github/workflows/ci.yml       # GitHub Actions CI 工作流（12 矩阵 + Lint）
├── pyproject.toml                 # 项目配置、依赖声明、ruff 配置
├── yuanzhao/
│   ├── __main__.py                # CLI 入口点
│   ├── cli.py                     # argparse 参数解析
│   ├── config.py                  # ScanConfig 数据类
│   ├── app.py                     # 应用编排（CLI → 扫描 → 报告）
│   ├── logging.py                 # 日志配置（Rich 输出）
│   ├── detectors/
│   │   ├── base.py                # Finding 数据类 + BaseDetector 抽象基类
│   │   ├── keyword.py             # 关键字匹配检测器
│   │   ├── html.py                # HTML 检测器（正则 + BeautifulSoup DOM 分析）
│   │   ├── javascript.py          # JavaScript 检测器
│   │   ├── css.py                 # CSS 检测器
│   │   ├── hiding.py              # 特殊隐藏技术检测器
│   │   ├── custom_rules.py        # 自定义规则检测器（YAML 驱动）
│   │   └── headless.py            # Chrome 无头浏览器检测器
│   ├── scanner/
│   │   ├── engine.py              # 扫描引擎（线程池、检测器调度）
│   │   └── targets.py             # 目标解析与分类
│   ├── reporters/
│   │   ├── base.py                # BaseReporter 抽象基类
│   │   ├── text.py                # 纯文本报告
│   │   ├── html.py                # Jinja2 HTML 报告
│   │   ├── json_reporter.py       # JSON 报告
│   │   └── csv_reporter.py        # CSV 报告
│   ├── network/
│   │   ├── client.py              # HTTP 请求（Session、TLS 适配器、重试）
│   │   └── utils.py               # URL 提取、域名解析、风险分析
│   ├── files/
│   │   └── utils.py               # 文件读取、编码检测、目录遍历
│   ├── rules/
│   │   ├── builtin.yaml           # 内置检测规则（CDN 白名单、TLD 权重等）
│   │   ├── keywords.csv           # 内置关键字表（198 条）
│   │   ├── custom_rules.example.yaml  # 自定义规则示例
│   │   └── loader.py              # 规则加载器
│   └── templates/
│       └── report.html            # Jinja2 HTML 报告模板
└── tests/                         # pytest 测试套件（192 个测试）
    ├── fixtures/                  # 测试用样本文件
    ├── test_config.py
    ├── test_network_utils.py
    ├── test_rules_loader.py
    ├── test_reporters.py
    ├── test_integration.py
    └── test_detectors/
        ├── test_base.py
        ├── test_keyword.py
        ├── test_html.py
        ├── test_javascript.py
        ├── test_css.py
        ├── test_hiding.py
        └── test_custom_rules.py
```

## 运行测试

```bash
# 安装开发依赖（含 pytest、ruff）
pip install -e ".[dev]"

# 运行全部 192 个测试
pytest

# 仅运行某个模块的测试
pytest tests/test_detectors/
pytest tests/test_integration.py

<<<<<<< HEAD
# 显示详细输出
pytest -v

# 代码检查
ruff check yuanzhao/ tests/
```

## 许可证

本工具仅供安全测试和应急响应使用。请确保对扫描目标拥有充分授权。

---

<a href="https://www.star-history.com/#KaneTheo/YuanZhao&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=KaneTheo/YuanZhao&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=KaneTheo/YuanZhao&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=KaneTheo/YuanZhao&type=date&legend=top-left" />
 </picture>
</a>

