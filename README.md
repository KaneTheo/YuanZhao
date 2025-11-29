# 渊照 - 专业暗链扫描工具

「渊照」是一款功能强大的专业暗链扫描工具，专注于检测网站、HTML文件或目录中的隐蔽链接、隐藏元素和恶意代码。该工具能够智能识别扫描目标类型（本地文件/目录、内网URL、公网URL），并自动调整扫描策略以获得最佳效果，是安全人员进行网站安全审计和应急响应的理想工具。

## 功能特性

### 智能目标识别与处理
- **多类型目标支持**：自动识别和扫描本地文件、本地目录、内网URL和公网URL
- **差异化扫描策略**：根据目标类型应用最优扫描策略
- **递归目录扫描**：支持可配置的扫描深度
- **文件过滤机制**：支持通过通配符排除特定文件或目录

### 核心扫描能力
- **多层次检测机制**：HTML代码检测、JavaScript代码分析、CSS代码检测、元标签扫描、注释内容分析
- **高级威胁识别**：加密/编码链接检测、可疑域名检测、随机生成域名检测、短链接服务检测、非标准端口检测、可疑查询参数检测
- **特殊隐藏手法检测**：CSS隐藏技术、颜色隐藏、零宽字符隐藏、字体大小隐藏等
- **关键字匹配系统**：支持CSV格式自定义关键字文件，包含关键字、类别和风险权重
- **智能风险评分**：基于多维度风险评估

### 无头浏览器增强检测
- **动态内容捕获**：使用Chrome无头浏览器执行JavaScript并捕获动态内容
- **DOM操作监控**：跟踪动态DOM修改
- **iframe深度分析**：渲染和分析iframe内容
- **网络请求捕获**：监控HTTP请求和重定向链

### 全面的报告系统
- **多种报告格式**：文本报告(txt)、HTML报告(html)、JSON报告(json)、CSV报告(csv)
- **丰富的报告内容**：扫描概览、问题详情、风险评估、上下文展示
- **来源类型标注**：在可疑链接中增加 `context_type` 字段（如 `html/js/css/comments`），用于区分链接的来源场景，便于后续数据分析与过滤
 - **来源标签与位置**：统一输出 `source_tag`（如 `debug/normal`）与定位范围 `position (start,end)`，HTML/CSV/JSON 报告保持一致

### 灵活的配置选项
- **多种扫描模式**：fast/standard/deep
- **性能优化选项**：可配置并发线程数、请求超时设置、代理服务器支持

## 安装指南

### 环境要求
- Python 3.8+

### 安装依赖
```bash
pip install -r requirements.txt
```

## 使用方法

### 查看帮助信息
```bash
python YuanZhao.py --help
```

### 完整使用案例命令

#### 1. 本地文件扫描场景
```bash
# 基本扫描 - 单个HTML文件
python YuanZhao.py /path/to/file.html

# 高级扫描 + HTML报告
python YuanZhao.py /path/to/file.html -m standard -f html

# 详细日志模式
python YuanZhao.py /path/to/suspicious.html --verbose

# 自定义输出目录
python YuanZhao.py /path/to/file.html -o /custom/report/dir

# 特定报告格式（JSON）
python YuanZhao.py /path/to/file.html -f json
```

#### 2. 本地目录扫描场景
```bash
# 默认深度扫描目录
python YuanZhao.py /path/to/website

# 自定义深度扫描（仅当前目录和一级子目录）
python YuanZhao.py /path/to/website -d 1

# 深度递归扫描
python YuanZhao.py /path/to/website -d 5

# 排除特定文件/目录
python YuanZhao.py /path/to/website --exclude "*.jpg" "*.png" "logs/*" "vendor/"

# 调整线程数（提高性能）
python YuanZhao.py /path/to/website -t 16

# 完整模式 + 多格式报告
python YuanZhao.py /path/to/website -m deep -f html -o security_reports --threads 12
```

#### 3. 网络URL扫描场景
```bash
# 基本网站扫描
python YuanZhao.py https://example.com

# 内网地址扫描
python YuanZhao.py http://192.168.1.100

# 本地开发服务器扫描
python YuanZhao.py http://localhost:8080

# 带路径的URL扫描
python YuanZhao.py https://example.com/news/article

# 设置超时时间（公网默认使用全局超时，内网未显式设置时会按较长超时）
python YuanZhao.py https://example.com --timeout 60

# 使用代理服务器
python YuanZhao.py https://example.com --proxy http://127.0.0.1:8080

# 带认证的代理
python YuanZhao.py https://example.com --proxy http://username:password@proxy.example.com:8080
```

#### 4. 高级功能场景
```bash
# 无头浏览器扫描（动态内容）
python YuanZhao.py https://dynamic-website.com --headless

# 无头浏览器 + 延长等待时间
python YuanZhao.py https://heavy-js-website.com --headless --js-wait 10

# 无头浏览器超时时间
python YuanZhao.py https://example.com --headless --headless-timeout 120

# 自定义关键字检测
python YuanZhao.py /path/to/target --keyword-file custom_keywords.txt

# 基础模式快速扫描
python YuanZhao.py https://example.com -m fast -d 1 -t 5

# 全部模式深度扫描
python YuanZhao.py /path/to/important-site -m deep -d 3 -f html --verbose
```

#### 5. 特定场景优化命令
```bash
# 应急响应场景
python YuanZhao.py /compromised/webroot -m deep -f html -o incident_response --keyword-file malware_keywords.txt --verbose

# 定期安全审计
python YuanZhao.py /path/to/webroot -d 3 -m standard -f json -o weekly_scan_$(date +%Y%m%d)

# 新闻页面专项扫描
python YuanZhao.py https://example.com/news -m deep -d 1 -t 8 --verbose

# 大规模并行扫描
python YuanZhao.py /large/website -d 2 -t 20 --exclude "*.zip" "*.rar" "backup/*"

# 自动化集成扫描（生成JSON报告）
python YuanZhao.py https://example.com -f json -o automated_scan_results --no-color
```
### 自定义关键字文件格式
```
关键字文件为CSV格式，每行包含三个字段：

关键字,类别,风险权重
poker,gambling,8
casino,gambling,9
malware,malware,10
phishing,phishing,9
```

类别可选值：gambling (博彩)、porn (色情)、malware (恶意软件)、phishing (钓鱼)、other (其他)
风险权重范围：1-10（10为最高风险）

## 主要参数说明

### 基本参数
- `target`: 扫描目标（文件路径、目录路径或URL）- 必需参数
- `-d, --depth`: 递归扫描深度（默认：3，0表示仅扫描当前文件/目录）
- `-m, --mode`: 扫描模式（fast/standard/deep，默认：deep）
- `-t, --threads`: 并发线程数（默认：8）

### 报告相关参数
- `-o, --output`: 报告输出目录（默认：./reports）
- `-f, --format`: 报告格式（txt/html/json/csv，默认：txt）

### 网络相关参数
- `--timeout`: 请求超时时间（秒，默认：30）。公网目标默认使用此值，内网目标未显式设置 `internal_timeout` 时按较长超时（约为全局超时的两倍）。
- `--proxy`: 代理设置（支持带认证与不带认证的HTTP代理），示例：`http://127.0.0.1:8080` 或 `http://user:pass@host:8080`

### 高级参数
- `--keyword-file`: 自定义关键字文件路径
- `--exclude`: 排除的文件或目录
- `--verbose`: 显示详细日志信息
- `--no-color`: 禁用彩色输出（适用于自动化脚本）

### 无头浏览器参数
- `--headless`: 启用无头浏览器扫描
- `--browser-type`: 无头浏览器类型（支持: chrome，默认: chrome）
- `--js-wait`: JavaScript执行等待时间（秒，默认: 3）
- `--headless-timeout`: 无头浏览器超时时间（秒，默认: 60）
 - `--headless-binary`: Chrome二进制路径（例如：`C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe`）
 - `--headless-driver`: ChromeDriver路径（例如：`C:\\drivers\\chromedriver.exe`）

## 常见问题解答

**Q: 扫描结果中的误报如何处理？**
A: 可以通过创建自定义关键字文件调整特定关键词的风险权重来减少误报，或结合扫描模式选择更精确的扫描策略。

**Q: 如何提高大型网站的扫描效率？**
A: 增加线程数、设置合理的爬取深度，或先使用基础模式（`fast`）进行初步筛选。对于公网网站，建议控制扫描范围。

**Q: 为什么有些动态生成的链接没被检测到？**
A: 启用无头浏览器模式`--headless`并适当增加JavaScript执行等待时间`--js-wait`。

**Q: 使用无头浏览器时需要注意什么？**
A: 使用无头浏览器会增加资源消耗和时间，建议适当降低线程数，为复杂页面增加等待时间，仅在必要时启用。

## 项目结构

```
YuanZhao/
├── YuanZhao.py           # 主程序入口
├── requirements.txt      # 依赖列表
├── README.md             # 项目说明
├── core/                 # 核心模块
│   ├── scanner.py        # 扫描引擎
│   ├── detector/         # 各类检测器
│   ├── reporter.py       # 报告生成器
│   └── config.py         # 配置管理
├── utils/                # 工具类
└── keywords_example.txt  # 关键字示例文件
```

## 许可证与免责声明

本工具仅供安全测试和应急响应使用，请确保您有足够的授权对目标进行扫描，避免对未经授权的系统进行测试。

## 开发者提示（工具接口）
- CSS工具正式接口：`extract_css_properties/remove_css_comments/extract_css_comments`
- 统一正式接口（`extract_css_properties/remove_css_comments/extract_css_comments`）。

## 开发者选项（日志与报告）
- `debug_log_wait_ms`：调试读取日志的初始等待时间（毫秒），默认 1500
- `debug_log_checks`：日志稳定性检查次数，默认 3
- `debug_log_interval_ms`：每次稳定性检查的间隔（毫秒），默认 500
- 提取统计日志级别：常规运行为 `debug`（匹配数与总提取数），在 `--verbose` 场景下查看更详细日志
- 报告来源字段：`context_type`（html/js/css/comments）与 `source_tag`（debug/normal）用于区分来源与路径
## Star History

<a href="https://www.star-history.com/#KaneTheo/YuanZhao&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=KaneTheo/YuanZhao&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=KaneTheo/YuanZhao&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=KaneTheo/YuanZhao&type=date&legend=top-left" />
 </picture>
</a>
