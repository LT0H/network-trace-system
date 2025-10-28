#!/usr/bin/env python
"""
测试运行脚本
支持运行特定类型的测试并生成报告
"""
import os
import sys
import subprocess
import argparse
import coverage

def run_unit_tests(verbose=False):
    """运行单元测试"""
    print("运行单元测试...")
    cmd = ['python', 'manage.py', 'test', 'scanner.tests']
    if verbose:
        cmd.append('-v')
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print("单元测试失败:", result.stderr)
        return False
    return True

def run_integration_tests(verbose=False):
    """运行集成测试"""
    print("运行集成测试...")
    cmd = ['python', 'manage.py', 'test', 'tests.integration']
    if verbose:
        cmd.append('-v')
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print("集成测试失败:", result.stderr)
        return False
    return True

def run_performance_tests():
    """运行性能测试"""
    print("运行性能测试...")
    # 性能测试可能需要特殊环境，这里简单运行
    cmd = ['python', 'manage.py', 'test', 'tests.performance', '-v', '0']
    result = subprocess.run(cmd)
    return result.returncode == 0

def run_security_tests():
    """运行安全测试"""
    print("运行安全测试...")
    cmd = ['python', 'manage.py', 'test', 'tests.security']
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    return result.returncode == 0

def generate_coverage_report():
    """生成测试覆盖率报告"""
    print("生成测试覆盖率报告...")
    cov = coverage.Coverage()
    cov.start()
    
    # 运行所有测试
    subprocess.run(['python', 'manage.py', 'test'])
    
    cov.stop()
    cov.save()
    cov.report()
    cov.html_report(directory='htmlcov')
    print("HTML报告已生成到 htmlcov/ 目录")

def main():
    parser = argparse.ArgumentParser(description='运行测试套件')
    parser.add_argument('--unit', action='store_true', help='运行单元测试')
    parser.add_argument('--integration', action='store_true', help='运行集成测试')
    parser.add_argument('--performance', action='store_true', help='运行性能测试')
    parser.add_argument('--security', action='store_true', help='运行安全测试')
    parser.add_argument('--all', action='store_true', help='运行所有测试')
    parser.add_argument('--coverage', action='store_true', help='生成覆盖率报告')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    # 设置Django环境
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings')
    
    success = True
    
    if args.all or args.unit:
        success &= run_unit_tests(args.verbose)
    
    if args.all or args.integration:
        success &= run_integration_tests(args.verbose)
    
    if args.all or args.performance:
        success &= run_performance_tests()
    
    if args.all or args.security:
        success &= run_security_tests()
    
    if args.coverage:
        generate_coverage_report()
    
    if not any([args.unit, args.integration, args.performance, args.security, args.all, args.coverage]):
        # 默认运行所有测试
        success = run_unit_tests(args.verbose) and run_integration_tests(args.verbose)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()