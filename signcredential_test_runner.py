#!/usr/bin/env python3
"""
SignCredential Security Test Runner
===================================

This script provides automated testing for the signCredential security fixes.
It includes test data generation, execution, and validation.

Usage:
    python signcredential_test_runner.py --test-type all
    python signcredential_test_runner.py --test-type input-validation
    python signcredential_test_runner.py --test-type access-control
"""

import requests
import json
import base64
import time
import argparse
import sys
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class TestResult:
    test_name: str
    status: str  # PASS, FAIL, ERROR
    expected_status: str
    actual_status: str
    response_time: float
    error_message: Optional[str] = None
    response_data: Optional[Dict] = None

class SignCredentialTester:
    def __init__(self, base_url: str, auth_token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.session = requests.Session()
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
    def make_request(self, test_data: Dict) -> requests.Response:
        """Make HTTP request to signCredential endpoint"""
        url = f"{self.base_url}/signCredential"
        return self.session.post(url, json=test_data, timeout=30)
    
    def generate_valid_test_data(self) -> Dict:
        """Generate valid test data"""
        valid_messages = [
            "SGVsbG8gV29ybGQ=",  # "Hello World"
            "VGVzdCBNZXNzYWdl",  # "Test Message"
            "Q3JlZGVudGlhbCBEYXRh",  # "Credential Data"
        ]
        
        return {
            "id": f"test-request-{int(time.time())}",
            "version": "1.0",
            "requesttime": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "request": {
                "message": valid_messages[0],
                "applicationId": "KERNEL",
                "referenceId": "SIGN"
            }
        }
    
    def generate_invalid_test_data(self, test_type: str) -> Dict:
        """Generate invalid test data based on test type"""
        base_data = self.generate_valid_test_data()
        
        if test_type == "null_message":
            base_data["request"]["message"] = None
        elif test_type == "empty_message":
            base_data["request"]["message"] = ""
        elif test_type == "invalid_base64":
            base_data["request"]["message"] = "Invalid@Base64#Format!"
        elif test_type == "large_message":
            # Generate message > 1MB
            large_data = "A" * 1048577  # > 1MB
            base_data["request"]["message"] = base64.b64encode(large_data.encode()).decode()
        elif test_type == "invalid_app_id":
            base_data["request"]["applicationId"] = "INVALID@APP#ID!"
        elif test_type == "invalid_ref_id":
            base_data["request"]["referenceId"] = "INVALID@REF#ID!"
        elif test_type == "unauthorized_app":
            base_data["request"]["applicationId"] = "UNAUTHORIZED_APP"
        
        return base_data
    
    def run_test(self, test_name: str, test_data: Dict, expected_status: int) -> TestResult:
        """Run a single test and return result"""
        start_time = time.time()
        
        try:
            response = self.make_request(test_data)
            response_time = time.time() - start_time
            
            status = "PASS" if response.status_code == expected_status else "FAIL"
            
            return TestResult(
                test_name=test_name,
                status=status,
                expected_status=str(expected_status),
                actual_status=str(response.status_code),
                response_time=response_time,
                response_data=response.json() if response.content else None
            )
            
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return TestResult(
                test_name=test_name,
                status="ERROR",
                expected_status=str(expected_status),
                actual_status="ERROR",
                response_time=response_time,
                error_message=str(e)
            )
    
    def run_input_validation_tests(self) -> List[TestResult]:
        """Run input validation tests"""
        print("🧪 Running Input Validation Tests...")
        results = []
        
        test_cases = [
            ("null_message", 400),
            ("empty_message", 400),
            ("invalid_base64", 400),
            ("large_message", 400),
            ("invalid_app_id", 400),
            ("invalid_ref_id", 400),
        ]
        
        for test_type, expected_status in test_cases:
            test_data = self.generate_invalid_test_data(test_type)
            result = self.run_test(f"Input Validation - {test_type}", test_data, expected_status)
            results.append(result)
            print(f"  {'✅' if result.status == 'PASS' else '❌'} {result.test_name}: {result.status}")
        
        return results
    
    def run_access_control_tests(self) -> List[TestResult]:
        """Run access control tests"""
        print("🔐 Running Access Control Tests...")
        results = []
        
        # Test unauthorized application
        test_data = self.generate_invalid_test_data("unauthorized_app")
        result = self.run_test("Access Control - Unauthorized App", test_data, 403)
        results.append(result)
        print(f"  {'✅' if result.status == 'PASS' else '❌'} {result.test_name}: {result.status}")
        
        return results
    
    def run_valid_request_tests(self) -> List[TestResult]:
        """Run valid request tests"""
        print("✅ Running Valid Request Tests...")
        results = []
        
        test_data = self.generate_valid_test_data()
        result = self.run_test("Valid Request", test_data, 200)
        results.append(result)
        print(f"  {'✅' if result.status == 'PASS' else '❌'} {result.test_name}: {result.status}")
        
        return results
    
    def run_performance_tests(self, num_requests: int = 10) -> List[TestResult]:
        """Run performance tests"""
        print(f"⚡ Running Performance Tests ({num_requests} requests)...")
        results = []
        
        def make_performance_request():
            test_data = self.generate_valid_test_data()
            return self.run_test("Performance Test", test_data, 200)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_performance_request) for _ in range(num_requests)]
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        total_time = time.time() - start_time
        avg_response_time = sum(r.response_time for r in results) / len(results)
        
        print(f"  📊 Total time: {total_time:.2f}s")
        print(f"  📊 Average response time: {avg_response_time:.2f}s")
        print(f"  📊 Requests per second: {num_requests/total_time:.2f}")
        
        return results
    
    def run_security_penetration_tests(self) -> List[TestResult]:
        """Run security penetration tests"""
        print("🛡️ Running Security Penetration Tests...")
        results = []
        
        # SQL Injection attempt
        test_data = self.generate_valid_test_data()
        test_data["request"]["applicationId"] = "KERNEL'; DROP TABLE users; --"
        result = self.run_test("Security - SQL Injection", test_data, 400)
        results.append(result)
        print(f"  {'✅' if result.status == 'PASS' else '❌'} {result.test_name}: {result.status}")
        
        # XSS attempt
        test_data = self.generate_valid_test_data()
        test_data["request"]["message"] = "<script>alert('XSS')</script>"
        result = self.run_test("Security - XSS Attempt", test_data, 400)
        results.append(result)
        print(f"  {'✅' if result.status == 'PASS' else '❌'} {result.test_name}: {result.status}")
        
        # Path traversal attempt
        test_data = self.generate_valid_test_data()
        test_data["request"]["applicationId"] = "../../etc/passwd"
        result = self.run_test("Security - Path Traversal", test_data, 400)
        results.append(result)
        print(f"  {'✅' if result.status == 'PASS' else '❌'} {result.test_name}: {result.status}")
        
        return results
    
    def run_all_tests(self) -> Dict[str, List[TestResult]]:
        """Run all test suites"""
        print("🚀 Starting Comprehensive Security Test Suite")
        print("=" * 50)
        
        all_results = {}
        
        # Run all test suites
        all_results["input_validation"] = self.run_input_validation_tests()
        all_results["access_control"] = self.run_access_control_tests()
        all_results["valid_requests"] = self.run_valid_request_tests()
        all_results["performance"] = self.run_performance_tests()
        all_results["security_penetration"] = self.run_security_penetration_tests()
        
        return all_results
    
    def generate_report(self, results: Dict[str, List[TestResult]]) -> str:
        """Generate test report"""
        report = []
        report.append("📊 SIGNCREDENTIAL SECURITY TEST REPORT")
        report.append("=" * 50)
        report.append("")
        
        total_tests = 0
        total_passed = 0
        total_failed = 0
        total_errors = 0
        
        for suite_name, suite_results in results.items():
            report.append(f"📋 {suite_name.upper().replace('_', ' ')} TESTS")
            report.append("-" * 30)
            
            passed = sum(1 for r in suite_results if r.status == "PASS")
            failed = sum(1 for r in suite_results if r.status == "FAIL")
            errors = sum(1 for r in suite_results if r.status == "ERROR")
            
            total_tests += len(suite_results)
            total_passed += passed
            total_failed += failed
            total_errors += errors
            
            report.append(f"Total: {len(suite_results)} | Passed: {passed} | Failed: {failed} | Errors: {errors}")
            report.append("")
            
            for result in suite_results:
                status_icon = "✅" if result.status == "PASS" else "❌" if result.status == "FAIL" else "⚠️"
                report.append(f"{status_icon} {result.test_name}")
                report.append(f"   Expected: {result.expected_status} | Actual: {result.actual_status}")
                report.append(f"   Response Time: {result.response_time:.3f}s")
                if result.error_message:
                    report.append(f"   Error: {result.error_message}")
                report.append("")
        
        # Summary
        report.append("📈 SUMMARY")
        report.append("-" * 20)
        report.append(f"Total Tests: {total_tests}")
        report.append(f"Passed: {total_passed} ({total_passed/total_tests*100:.1f}%)")
        report.append(f"Failed: {total_failed} ({total_failed/total_tests*100:.1f}%)")
        report.append(f"Errors: {total_errors} ({total_errors/total_tests*100:.1f}%)")
        report.append("")
        
        if total_failed == 0 and total_errors == 0:
            report.append("🎉 ALL TESTS PASSED! Security fixes are working correctly.")
        else:
            report.append("⚠️  Some tests failed. Please review the results above.")
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="SignCredential Security Test Runner")
    parser.add_argument("--base-url", required=True, help="Base URL of the service")
    parser.add_argument("--auth-token", help="Authentication token (optional)")
    parser.add_argument("--test-type", choices=["all", "input-validation", "access-control", "valid-requests", "performance", "security-penetration"], 
                       default="all", help="Type of tests to run")
    parser.add_argument("--output-file", help="Output file for test report")
    
    args = parser.parse_args()
    
    # Initialize tester
    tester = SignCredentialTester(args.base_url, args.auth_token)
    
    # Run tests based on type
    if args.test_type == "all":
        results = tester.run_all_tests()
    elif args.test_type == "input-validation":
        results = {"input_validation": tester.run_input_validation_tests()}
    elif args.test_type == "access-control":
        results = {"access_control": tester.run_access_control_tests()}
    elif args.test_type == "valid-requests":
        results = {"valid_requests": tester.run_valid_request_tests()}
    elif args.test_type == "performance":
        results = {"performance": tester.run_performance_tests()}
    elif args.test_type == "security-penetration":
        results = {"security_penetration": tester.run_security_penetration_tests()}
    
    # Generate and display report
    report = tester.generate_report(results)
    print("\n" + report)
    
    # Save report to file if specified
    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(report)
        print(f"\n📄 Report saved to: {args.output_file}")
    
    # Exit with appropriate code
    total_failed = sum(sum(1 for r in suite_results if r.status in ["FAIL", "ERROR"]) 
                      for suite_results in results.values())
    sys.exit(0 if total_failed == 0 else 1)

if __name__ == "__main__":
    main()
