#!/usr/bin/env python3
"""
HP PrintOS Dashboard API Testing Script
Tests all backend endpoints for functionality and data integrity
"""

import requests
import sys
import json
from datetime import datetime

class HPPrintOSAPITester:
    def __init__(self, base_url="https://ink-tracker-6.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details="", response_data=None):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name}")
        else:
            print(f"❌ {name} - {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details,
            "response_data": response_data
        })

    def run_test(self, name, method, endpoint, expected_status=200, params=None, data=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, params=params, timeout=30)
            
            success = response.status_code == expected_status
            
            if success:
                try:
                    response_json = response.json()
                    self.log_test(name, True, f"Status: {response.status_code}", response_json)
                    return True, response_json
                except:
                    self.log_test(name, True, f"Status: {response.status_code} (non-JSON response)")
                    return True, response.text
            else:
                self.log_test(name, False, f"Expected {expected_status}, got {response.status_code}: {response.text}")
                return False, {}

        except Exception as e:
            self.log_test(name, False, f"Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test GET /api/ - Root endpoint"""
        success, response = self.run_test(
            "Root API endpoint",
            "GET", 
            "",
            200
        )
        
        if success and isinstance(response, dict):
            if "message" in response and "version" in response:
                self.log_test("Root endpoint structure", True, "Contains message and version")
                return True
            else:
                self.log_test("Root endpoint structure", False, "Missing message or version fields")
        
        return success

    def test_devices_endpoint(self):
        """Test GET /api/devices - Returns list of 3 devices"""
        success, response = self.run_test(
            "Devices list endpoint",
            "GET",
            "devices",
            200
        )
        
        if success and isinstance(response, list):
            if len(response) == 3:
                self.log_test("Devices count", True, f"Found {len(response)} devices")
                
                # Check device structure
                required_fields = ["id", "name", "model", "status"]
                for i, device in enumerate(response):
                    missing_fields = [field for field in required_fields if field not in device]
                    if missing_fields:
                        self.log_test(f"Device {i+1} structure", False, f"Missing fields: {missing_fields}")
                    else:
                        self.log_test(f"Device {i+1} structure", True, f"Device: {device['name']} ({device['model']})")
                
                return True
            else:
                self.log_test("Devices count", False, f"Expected 3 devices, got {len(response)}")
        
        return success

    def test_stats_overview(self):
        """Test GET /api/stats/overview - Returns stats with jobs, impressions, success_rate"""
        success, response = self.run_test(
            "Stats overview endpoint",
            "GET",
            "stats/overview",
            200
        )
        
        if success and isinstance(response, dict):
            required_fields = ["total_jobs", "total_impressions", "success_rate", "printed_jobs", "aborted_jobs"]
            missing_fields = [field for field in required_fields if field not in response]
            
            if missing_fields:
                self.log_test("Stats overview structure", False, f"Missing fields: {missing_fields}")
            else:
                self.log_test("Stats overview structure", True, 
                    f"Jobs: {response['total_jobs']}, Impressions: {response['total_impressions']}, Success: {response['success_rate']}%")
                return True
        
        return success

    def test_jobs_endpoint(self):
        """Test GET /api/jobs - Returns paginated jobs list with filters"""
        # Test basic jobs endpoint
        success, response = self.run_test(
            "Jobs list endpoint",
            "GET",
            "jobs",
            200
        )
        
        if success and isinstance(response, dict):
            required_fields = ["jobs", "total", "page", "limit", "pages"]
            missing_fields = [field for field in required_fields if field not in response]
            
            if missing_fields:
                self.log_test("Jobs list structure", False, f"Missing fields: {missing_fields}")
            else:
                jobs_count = len(response.get("jobs", []))
                self.log_test("Jobs list structure", True, 
                    f"Found {jobs_count} jobs, Total: {response['total']}, Pages: {response['pages']}")
                
                # Test job structure if jobs exist
                if jobs_count > 0:
                    job = response["jobs"][0]
                    job_fields = ["marker", "press_id", "job_name", "status", "total_impressions", "click_category"]
                    missing_job_fields = [field for field in job_fields if field not in job]
                    
                    if missing_job_fields:
                        self.log_test("Job structure", False, f"Missing job fields: {missing_job_fields}")
                    else:
                        self.log_test("Job structure", True, f"Job: {job.get('job_name', 'N/A')} - {job.get('click_category', 'N/A')}")
                
                return True
        
        return success

    def test_jobs_with_filters(self):
        """Test jobs endpoint with various filters"""
        # Test device filter
        success, _ = self.run_test(
            "Jobs with device filter",
            "GET",
            "jobs",
            200,
            params={"device_id": "47100122", "limit": 10}
        )
        
        # Test status filter
        success2, _ = self.run_test(
            "Jobs with status filter",
            "GET",
            "jobs",
            200,
            params={"status": "PRINTED", "limit": 10}
        )
        
        # Test category filter
        success3, _ = self.run_test(
            "Jobs with category filter",
            "GET",
            "jobs",
            200,
            params={"click_category": "Multicolor", "limit": 10}
        )
        
        return success and success2 and success3

    def test_clicks_report(self):
        """Test GET /api/clicks/report - Returns click categories breakdown"""
        success, response = self.run_test(
            "Clicks report endpoint",
            "GET",
            "clicks/report",
            200
        )
        
        if success and isinstance(response, dict):
            required_fields = ["total_impressions", "one_color", "two_colors", "epm", "multicolor", "categories"]
            missing_fields = [field for field in required_fields if field not in response]
            
            if missing_fields:
                self.log_test("Clicks report structure", False, f"Missing fields: {missing_fields}")
            else:
                self.log_test("Clicks report structure", True, 
                    f"Total: {response['total_impressions']}, Categories: {len(response.get('categories', []))}")
                return True
        
        return success

    def test_clicks_export(self):
        """Test GET /api/clicks/export - Returns CSV file"""
        url = f"{self.base_url}/clicks/export"
        
        try:
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '')
                if 'csv' in content_type or 'text' in content_type:
                    # Check if response contains CSV-like content
                    content = response.text
                    if 'Job Name' in content and ',' in content:
                        lines_count = len(content.split('\n'))
                        self.log_test("Clicks CSV export", True, f"CSV export successful, {lines_count} lines")
                        return True
                    else:
                        self.log_test("Clicks CSV export", False, "Response doesn't look like CSV")
                else:
                    self.log_test("Clicks CSV export", False, f"Wrong content type: {content_type}")
            else:
                self.log_test("Clicks CSV export", False, f"Status: {response.status_code}")
                
        except Exception as e:
            self.log_test("Clicks CSV export", False, f"Error: {str(e)}")
        
        return False

    def test_device_specific_endpoints(self):
        """Test device-specific endpoints"""
        device_id = "47100122"  # 9129 device
        
        # Test device status
        success1, _ = self.run_test(
            f"Device {device_id} status",
            "GET",
            f"devices/{device_id}/status",
            200
        )
        
        # Test device performance
        success2, _ = self.run_test(
            f"Device {device_id} performance",
            "GET",
            f"devices/{device_id}/performance",
            200
        )
        
        return success1 and success2

    def test_sync_endpoint(self):
        """Test POST /api/jobs/sync - Job synchronization"""
        success, response = self.run_test(
            "Jobs sync endpoint",
            "POST",
            "jobs/sync",
            200,
            params={"device_id": "47100122"}
        )
        
        if success and isinstance(response, dict):
            required_fields = ["status", "jobs_synced", "last_marker", "message"]
            missing_fields = [field for field in required_fields if field not in response]
            
            if missing_fields:
                self.log_test("Sync response structure", False, f"Missing fields: {missing_fields}")
            else:
                self.log_test("Sync response structure", True, 
                    f"Status: {response['status']}, Jobs synced: {response['jobs_synced']}")
                return True
        
        return success

    def run_all_tests(self):
        """Run all API tests"""
        print("🔍 Starting HP PrintOS Dashboard API Tests...")
        print(f"📡 Testing against: {self.base_url}")
        print("=" * 60)
        
        # Core API tests
        self.test_root_endpoint()
        self.test_devices_endpoint()
        self.test_stats_overview()
        self.test_jobs_endpoint()
        self.test_jobs_with_filters()
        self.test_clicks_report()
        self.test_clicks_export()
        self.test_device_specific_endpoints()
        self.test_sync_endpoint()
        
        # Summary
        print("=" * 60)
        print(f"📊 Tests completed: {self.tests_passed}/{self.tests_run} passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return 0
        else:
            print(f"⚠️  {self.tests_run - self.tests_passed} tests failed")
            return 1

    def get_test_summary(self):
        """Get test summary for reporting"""
        return {
            "total_tests": self.tests_run,
            "passed_tests": self.tests_passed,
            "failed_tests": self.tests_run - self.tests_passed,
            "success_rate": round((self.tests_passed / max(self.tests_run, 1)) * 100, 1),
            "test_results": self.test_results
        }

def main():
    tester = HPPrintOSAPITester()
    exit_code = tester.run_all_tests()
    
    # Save detailed results
    summary = tester.get_test_summary()
    with open('/app/backend_test_results.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    return exit_code

if __name__ == "__main__":
    sys.exit(main())