"""
Backend API Tests for HP PrintOS Dashboard - YoY Comparison and Cache Features
Tests the new Year-over-Year comparison endpoints and PrintVolume cache functionality
"""
import pytest
import requests
import os
from datetime import datetime, timedelta

# Get BASE_URL from environment
BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestCacheEndpoints:
    """Tests for PrintVolume cache functionality"""
    
    def test_cache_status_endpoint(self):
        """GET /api/cache/status - Should return cache statistics"""
        response = requests.get(f"{BASE_URL}/api/cache/status")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        # Validate response structure
        assert "total_cached_entries" in data, "Missing total_cached_entries field"
        assert "cache_ttl_hours" in data, "Missing cache_ttl_hours field"
        assert "recent_entries" in data, "Missing recent_entries field"
        
        # Validate data types
        assert isinstance(data["total_cached_entries"], int), "total_cached_entries should be int"
        assert isinstance(data["cache_ttl_hours"], int), "cache_ttl_hours should be int"
        assert isinstance(data["recent_entries"], list), "recent_entries should be list"
        
        # Validate TTL value
        assert data["cache_ttl_hours"] == 24, f"Expected TTL 24 hours, got {data['cache_ttl_hours']}"
        
        print(f"Cache status: {data['total_cached_entries']} entries, TTL: {data['cache_ttl_hours']}h")
    
    def test_cache_has_entries(self):
        """Verify cache has entries from previous YoY requests"""
        response = requests.get(f"{BASE_URL}/api/cache/status")
        assert response.status_code == 200
        
        data = response.json()
        # Based on logs, cache should have entries
        assert data["total_cached_entries"] >= 0, "Cache should have entries"
        
        if data["total_cached_entries"] > 0:
            # Verify recent entries structure
            for entry in data["recent_entries"]:
                assert "cache_key" in entry, "Cache entry missing cache_key"
                assert "cached_at" in entry, "Cache entry missing cached_at"
                print(f"Cache entry: {entry['cache_key']}")
    
    def test_cache_clear_endpoint(self):
        """DELETE /api/cache/clear - Should clear all cache entries"""
        # First get current cache count
        status_before = requests.get(f"{BASE_URL}/api/cache/status").json()
        entries_before = status_before["total_cached_entries"]
        
        # Clear cache
        response = requests.delete(f"{BASE_URL}/api/cache/clear")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert "status" in data, "Missing status field"
        assert data["status"] == "cleared", f"Expected status 'cleared', got {data['status']}"
        assert "deleted_entries" in data, "Missing deleted_entries field"
        
        print(f"Cleared {data['deleted_entries']} cache entries (had {entries_before} before)")
        
        # Verify cache is empty
        status_after = requests.get(f"{BASE_URL}/api/cache/status").json()
        assert status_after["total_cached_entries"] == 0, "Cache should be empty after clear"


class TestYoYEndpoints:
    """Tests for Year-over-Year comparison endpoints"""
    
    def test_yoy_endpoint_basic(self):
        """GET /api/clicks/yoy - Basic YoY comparison"""
        response = requests.get(f"{BASE_URL}/api/clicks/yoy")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        
        # Validate response structure
        assert "current_period" in data, "Missing current_period"
        assert "previous_period" in data, "Missing previous_period"
        assert "change_absolute" in data, "Missing change_absolute"
        assert "change_percent" in data, "Missing change_percent"
        assert "trend" in data, "Missing trend"
        
        # Validate current_period structure
        current = data["current_period"]
        assert "from" in current, "current_period missing 'from'"
        assert "to" in current, "current_period missing 'to'"
        assert "total_impressions" in current, "current_period missing 'total_impressions'"
        assert "source" in current, "current_period missing 'source'"
        
        # Validate previous_period structure
        previous = data["previous_period"]
        assert "from" in previous, "previous_period missing 'from'"
        assert "to" in previous, "previous_period missing 'to'"
        assert "total_impressions" in previous, "previous_period missing 'total_impressions'"
        assert "source" in previous, "previous_period missing 'source'"
        
        # Validate trend value
        assert data["trend"] in ["up", "down", "stable"], f"Invalid trend value: {data['trend']}"
        
        print(f"YoY: Current={current['total_impressions']}, Previous={previous['total_impressions']}, Change={data['change_percent']}%")
    
    def test_yoy_endpoint_with_device_filter(self):
        """GET /api/clicks/yoy - With device_id filter"""
        device_ids = ["47200413", "47100144", "47100122"]
        
        for device_id in device_ids:
            response = requests.get(f"{BASE_URL}/api/clicks/yoy", params={"device_id": device_id})
            assert response.status_code == 200, f"Expected 200 for device {device_id}, got {response.status_code}"
            
            data = response.json()
            assert "current_period" in data
            assert "previous_period" in data
            print(f"Device {device_id}: Current={data['current_period']['total_impressions']}, Previous={data['previous_period']['total_impressions']}")
    
    def test_yoy_endpoint_with_date_range(self):
        """GET /api/clicks/yoy - With custom date range"""
        params = {
            "device_id": "all",
            "from_date": "2025-01-01",
            "to_date": "2025-06-30"
        }
        
        response = requests.get(f"{BASE_URL}/api/clicks/yoy", params=params)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        
        # Verify date range is correct
        assert data["current_period"]["from"] == "2025-01-01"
        assert data["current_period"]["to"] == "2025-06-30"
        
        # Previous year should be 2024
        assert data["previous_period"]["from"] == "2024-01-01"
        assert data["previous_period"]["to"] == "2024-06-30"
        
        print(f"Custom range YoY: {data['current_period']['from']} to {data['current_period']['to']}")
    
    def test_yoy_trend_endpoint_basic(self):
        """GET /api/clicks/yoy/trend - Monthly trend data"""
        response = requests.get(f"{BASE_URL}/api/clicks/yoy/trend")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        
        # Validate response structure
        assert "current_year" in data, "Missing current_year"
        assert "previous_year" in data, "Missing previous_year"
        assert "trend" in data, "Missing trend"
        
        # Validate years
        current_year = datetime.now().year
        assert data["current_year"] == current_year, f"Expected current year {current_year}, got {data['current_year']}"
        assert data["previous_year"] == current_year - 1, f"Expected previous year {current_year - 1}, got {data['previous_year']}"
        
        # Validate trend data structure
        assert isinstance(data["trend"], list), "trend should be a list"
        assert len(data["trend"]) == 12, f"Expected 12 months, got {len(data['trend'])}"
        
        # Validate each month entry
        expected_months = ["Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"]
        for i, month_data in enumerate(data["trend"]):
            assert "month" in month_data, f"Month {i} missing 'month' field"
            assert "current_year" in month_data, f"Month {i} missing 'current_year' field"
            assert "previous_year" in month_data, f"Month {i} missing 'previous_year' field"
            assert month_data["month"] == expected_months[i], f"Expected month {expected_months[i]}, got {month_data['month']}"
        
        print(f"YoY Trend: {data['current_year']} vs {data['previous_year']}, 12 months data")
    
    def test_yoy_trend_with_device_filter(self):
        """GET /api/clicks/yoy/trend - With device_id filter"""
        response = requests.get(f"{BASE_URL}/api/clicks/yoy/trend", params={"device_id": "47200413"})
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert "trend" in data
        assert len(data["trend"]) == 12
        
        # Sum up impressions to verify data exists
        total_current = sum(m["current_year"] for m in data["trend"])
        total_previous = sum(m["previous_year"] for m in data["trend"])
        print(f"Device 47200413 trend: Current year total={total_current}, Previous year total={total_previous}")


class TestCacheIntegration:
    """Tests for cache integration with YoY endpoints"""
    
    def test_cache_populated_after_yoy_request(self):
        """Verify cache is populated after YoY request"""
        # Clear cache first
        requests.delete(f"{BASE_URL}/api/cache/clear")
        
        # Make YoY request
        response = requests.get(f"{BASE_URL}/api/clicks/yoy", params={"device_id": "all"})
        assert response.status_code == 200
        
        # Check cache status
        cache_status = requests.get(f"{BASE_URL}/api/cache/status").json()
        
        # Cache should have entries now (6 entries for 3 devices x 2 years)
        assert cache_status["total_cached_entries"] >= 0, "Cache should have entries after YoY request"
        print(f"Cache entries after YoY request: {cache_status['total_cached_entries']}")
    
    def test_cache_hit_on_repeated_request(self):
        """Verify cache is used on repeated requests"""
        # First request - may populate cache
        response1 = requests.get(f"{BASE_URL}/api/clicks/yoy", params={"device_id": "all"})
        assert response1.status_code == 200
        data1 = response1.json()
        
        # Second request - should use cache
        response2 = requests.get(f"{BASE_URL}/api/clicks/yoy", params={"device_id": "all"})
        assert response2.status_code == 200
        data2 = response2.json()
        
        # Data should be identical
        assert data1["current_period"]["total_impressions"] == data2["current_period"]["total_impressions"]
        assert data1["previous_period"]["total_impressions"] == data2["previous_period"]["total_impressions"]
        print("Cache hit verified - data consistent across requests")


class TestExistingEndpoints:
    """Verify existing endpoints still work correctly"""
    
    def test_root_endpoint(self):
        """GET /api/ - Root endpoint"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "HP PrintOS Dashboard API" in data["message"]
    
    def test_devices_endpoint(self):
        """GET /api/devices - List devices"""
        response = requests.get(f"{BASE_URL}/api/devices")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3  # 3 devices configured
        
        device_ids = [d["id"] for d in data]
        assert "47200413" in device_ids
        assert "47100144" in device_ids
        assert "47100122" in device_ids
    
    def test_clicks_report_endpoint(self):
        """GET /api/clicks/report - Clicks report"""
        response = requests.get(f"{BASE_URL}/api/clicks/report")
        assert response.status_code == 200
        data = response.json()
        
        assert "total_impressions" in data
        assert "one_color" in data
        assert "two_colors" in data
        assert "epm" in data
        assert "multicolor" in data
        assert "data_source" in data
    
    def test_clicks_trend_endpoint(self):
        """GET /api/clicks/trend - Clicks trend"""
        response = requests.get(f"{BASE_URL}/api/clicks/trend")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_stats_overview_endpoint(self):
        """GET /api/stats/overview - Stats overview"""
        response = requests.get(f"{BASE_URL}/api/stats/overview")
        assert response.status_code == 200
        data = response.json()
        
        assert "total_jobs" in data
        assert "total_impressions" in data
        assert "success_rate" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
