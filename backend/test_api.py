"""
Test Flask API Endpoints
Simple script to verify your honeypot backend is working
"""

import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_health():
    """Test health endpoint"""
    print("="*60)
    print("Testing /health endpoint")
    print("="*60)
    
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response:")
        print(json.dumps(response.json(), indent=2))
        print()
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        print("Make sure Flask is running: python app.py")
        return False

def test_track_sql_injection():
    """Test SQL injection detection"""
    print("="*60)
    print("Test 1: SQL Injection Detection")
    print("="*60)
    
    payload = {
        "email": "admin' OR 1=1--",
        "password": "test123",
        "mouse_movements": 5,
        "keystrokes": 3,
        "time_to_submit": 0.5,
        "honeypot_filled": 0,
        "rapid_submission": 1
    }
    
    print("Sending payload:")
    print(json.dumps(payload, indent=2))
    print()
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/track",
            json=payload,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("\nResponse:")
            print(json.dumps(data, indent=2))
            
            # Verify detection
            print("\n" + "-"*60)
            print("Detection Summary:")
            print(f"  Is Attack: {data.get('is_attack')}")
            print(f"  Attack Type: {data.get('attack_type')}")
            print(f"  Severity: {data.get('severity')}")
            print(f"  CVSS Score: {data.get('cvss_score')}")
            print(f"  Is Bot: {data.get('is_bot')}")
            
            if data.get('vulnerabilities'):
                print(f"\n  Vulnerabilities Detected: {len(data['vulnerabilities'])}")
                for vuln in data['vulnerabilities']:
                    print(f"    - {vuln.get('name')} (CVSS: {vuln.get('cvss_score')})")
            
            if data.get('is_attack'):
                print("\n✅ SQL Injection detected successfully!")
            else:
                print("\n⚠️  Attack was NOT detected")
        else:
            print(f"❌ Error response:")
            print(response.text)
        
        print()
        return response.status_code == 200
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_track_xss():
    """Test XSS detection"""
    print("="*60)
    print("Test 2: XSS Detection")
    print("="*60)
    
    payload = {
        "email": "user@example.com",
        "comment": "<script>alert('XSS')</script>",
        "mouse_movements": 50,
        "keystrokes": 30,
        "time_to_submit": 5.0
    }
    
    print("Sending payload:")
    print(json.dumps(payload, indent=2))
    print()
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/track",
            json=payload,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("\nDetection Summary:")
            print(f"  Is Attack: {data.get('is_attack')}")
            print(f"  Attack Type: {data.get('attack_type')}")
            print(f"  Severity: {data.get('severity')}")
            print(f"  CVSS Score: {data.get('cvss_score')}")
            
            if data.get('is_attack'):
                print("\n✅ XSS detected successfully!")
            else:
                print("\n⚠️  Attack was NOT detected")
        
        print()
        return response.status_code == 200
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_track_benign():
    """Test benign (legitimate) traffic"""
    print("="*60)
    print("Test 3: Benign Traffic")
    print("="*60)
    
    payload = {
        "email": "user@example.com",
        "password": "MyPassword123",
        "mouse_movements": 150,
        "keystrokes": 80,
        "time_to_submit": 12.5,
        "honeypot_filled": 0,
        "rapid_submission": 0
    }
    
    print("Sending benign payload:")
    print(json.dumps(payload, indent=2))
    print()
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/track",
            json=payload,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("\nDetection Summary:")
            print(f"  Is Attack: {data.get('is_attack')}")
            print(f"  Attack Type: {data.get('attack_type')}")
            print(f"  Is Bot: {data.get('is_bot')}")
            
            if not data.get('is_attack'):
                print("\n✅ Correctly identified as legitimate!")
            else:
                print("\n⚠️  False positive - marked as attack")
        
        print()
        return response.status_code == 200
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_stats():
    """Test stats endpoint"""
    print("="*60)
    print("Test 4: Stats Endpoint")
    print("="*60)
    
    try:
        response = requests.get(f"{BASE_URL}/api/stats", timeout=10)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\nStats Summary:")
            print(f"  Total Events: {data.get('total_events')}")
            print(f"  Total Attacks: {data.get('total_attacks')}")
            print(f"  Avg CVSS Score: {data.get('avg_cvss_score')}")
            
            if data.get('severity_distribution'):
                print(f"\n  Severity Distribution:")
                for severity, count in data['severity_distribution'].items():
                    print(f"    {severity}: {count}")
            
            print("\n✅ Stats retrieved successfully!")
        
        print()
        return response.status_code == 200
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("HONEYPOT BACKEND API TESTS")
    print("="*60)
    print()
    
    # Test health first
    if not test_health():
        print("\n❌ Backend is not running!")
        print("Start it with: python app.py")
        return
    
    # Run all tests
    results = []
    results.append(("SQL Injection Detection", test_track_sql_injection()))
    results.append(("XSS Detection", test_track_xss()))
    results.append(("Benign Traffic", test_track_benign()))
    results.append(("Stats Endpoint", test_stats()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("🎉 All tests passed! Your honeypot is working perfectly!")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    main()
