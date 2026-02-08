#!/usr/bin/env python3
"""
Honeypot Training Data Generator
Generates synthetic attack and legitimate user data for XGBoost training
"""

import pandas as pd
import random
import json
from datetime import datetime, timedelta

def generate_training_data(num_samples=5000, save_format='both'):
    """
    Generate synthetic honeypot training data
    
    Args:
        num_samples: Number of samples to generate (default 5000)
        save_format: 'csv', 'json', or 'both' (default 'both')
    
    Returns:
        DataFrame with training data
    """
    
    print(f"🚀 Generating {num_samples} training samples...")
    data = []
    attack_count = 0
    
    # SQL Injection patterns
    sql_patterns = [
        "admin' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
        "admin' UNION SELECT",
        "'; DROP TABLE users--",
        "' OR 'a'='a",
        "admin' OR '1'='1'--",
        "1' AND '1'='1",
        "' UNION SELECT NULL--",
        "admin'/*"
    ]
    
    # XSS patterns
    xss_patterns = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert(1) autofocus>"
    ]
    
    # Command injection patterns
    cmd_patterns = [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "; rm -rf /",
        "| nc -e /bin/sh",
        "`cat /etc/shadow`"
    ]
    
    # Path traversal patterns
    path_patterns = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..\\..\\..\\windows\\system32"
    ]
    
    for i in range(num_samples):
        # Decide if this is an attack (30% attack rate)
        is_attack = random.random() < 0.3
        
        if is_attack:
            attack_count += 1
            # Choose attack type
            attack_type = random.choice(['sql', 'xss', 'cmd', 'path', 'bot', 'brute_force'])
            
            if attack_type == 'sql':
                email = random.choice(sql_patterns)
                password = random.choice(['test', 'admin', '123', ''])
                mouse_movements = random.randint(0, 3)
                time_to_submit = round(random.uniform(0.1, 1.5), 2)
                honeypot_filled = random.choice([0, 1])
                keystrokes = random.randint(5, 20)
                focus_events = random.randint(0, 2)
                paste_events = random.choice([0, 1])
                attack_label = 'sql_injection'
                
            elif attack_type == 'xss':
                email = random.choice(xss_patterns)
                password = random.choice(['test', 'pass', ''])
                mouse_movements = random.randint(0, 2)
                time_to_submit = round(random.uniform(0.2, 1.0), 2)
                honeypot_filled = 0
                keystrokes = len(email)
                focus_events = random.randint(0, 1)
                paste_events = 1
                attack_label = 'xss'
                
            elif attack_type == 'cmd':
                email = f"test@test.com{random.choice(cmd_patterns)}"
                password = random.choice(cmd_patterns)
                mouse_movements = random.randint(0, 2)
                time_to_submit = round(random.uniform(0.1, 0.8), 2)
                honeypot_filled = 0
                keystrokes = random.randint(10, 25)
                focus_events = random.randint(0, 2)
                paste_events = 1
                attack_label = 'command_injection'
                
            elif attack_type == 'path':
                email = random.choice(path_patterns)
                password = 'test'
                mouse_movements = random.randint(0, 2)
                time_to_submit = round(random.uniform(0.2, 1.2), 2)
                honeypot_filled = 0
                keystrokes = len(email)
                focus_events = random.randint(0, 1)
                paste_events = 1
                attack_label = 'path_traversal'
                
            elif attack_type == 'bot':
                email = f"bot{i}@automated.com"
                password = f"botpass{random.randint(1000, 9999)}"
                mouse_movements = 0
                time_to_submit = round(random.uniform(0.1, 0.5), 2)
                honeypot_filled = 1
                keystrokes = 0
                focus_events = 0
                paste_events = 1
                attack_label = 'bot'
                
            else:  # brute_force
                email = random.choice(['admin', 'root', 'administrator', 'test'])
                password = f"pass{random.randint(1, 999)}"
                mouse_movements = random.randint(0, 1)
                time_to_submit = round(random.uniform(0.3, 1.0), 2)
                honeypot_filled = 0
                keystrokes = random.randint(3, 10)
                focus_events = random.randint(0, 2)
                paste_events = 0
                attack_label = 'brute_force'
            
        else:
            # Generate legitimate user behavior
            email = f"user{i}@{''.join(random.choices(['gmail', 'yahoo', 'outlook', 'company'], k=1))}.com"
            password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(8, 16)))
            mouse_movements = random.randint(5, 50)
            time_to_submit = round(random.uniform(2.0, 20.0), 2)
            honeypot_filled = 0
            keystrokes = len(email) + len(password) + random.randint(0, 10)
            focus_events = random.randint(2, 10)
            paste_events = random.choice([0, 0, 0, 1])
            attack_label = 'legitimate'
        
        # Calculate derived features
        honeypot_total_length = len(email) if honeypot_filled else 0
        email_length = len(email)
        password_length = len(password)
        cookies_enabled = 1
        
        # Create timestamp
        timestamp = (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
        
        # Add to dataset
        data.append({
            'session_id': f'session_{i:06d}',
            'timestamp': timestamp,
            'email': email,
            'password': '***' if not is_attack else password,
            'mouse_movements': mouse_movements,
            'time_to_submit': time_to_submit,
            'honeypot_filled': honeypot_filled,
            'honeypot_total_length': honeypot_total_length,
            'keystrokes': keystrokes,
            'focus_events': focus_events,
            'paste_events': paste_events,
            'email_length': email_length,
            'password_length': password_length,
            'cookies_enabled': cookies_enabled,
            'is_attack': 1 if is_attack else 0,
            'attack_type': attack_label
        })
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Print statistics
    print(f"\n✅ Generated {len(df)} samples")
    print(f"   📊 Distribution:")
    print(f"      • Legitimate users: {len(df[df['is_attack'] == 0])} ({len(df[df['is_attack'] == 0])/len(df)*100:.1f}%)")
    print(f"      • Attacks: {len(df[df['is_attack'] == 1])} ({len(df[df['is_attack'] == 1])/len(df)*100:.1f}%)")
    print(f"\n   🎯 Attack Types:")
    for attack_type in df[df['is_attack'] == 1]['attack_type'].value_counts().items():
        print(f"      • {attack_type[0]}: {attack_type[1]}")
    
    # Save files
    if save_format in ['csv', 'both']:
        csv_file = 'honeypot_training_data.csv'
        df.to_csv(csv_file, index=False)
        print(f"\n💾 Saved CSV: {csv_file}")
    
    if save_format in ['json', 'both']:
        json_file = 'honeypot_training_data.json'
        df.to_json(json_file, orient='records', indent=2)
        print(f"💾 Saved JSON: {json_file}")
    
    # Create a smaller sample file for testing
    sample_df = df.sample(n=min(100, len(df)))
    sample_df.to_csv('honeypot_training_sample.csv', index=False)
    print(f"💾 Saved Sample (100 rows): honeypot_training_sample.csv")
    
    return df


if __name__ == '__main__':
    print("=" * 60)
    print("  HONEYPOT TRAINING DATA GENERATOR")
    print("=" * 60)
    
    # Generate main dataset
    print("\n1️⃣ Generating main training dataset...")
    df = generate_training_data(num_samples=5000, save_format='both')
    
    print("\n" + "=" * 60)
    print("  ✅ ALL FILES GENERATED SUCCESSFULLY!")
    print("=" * 60)
    print("\nFiles created:")
    print("  1. honeypot_training_data.csv (main dataset - ~500KB)")
    print("  2. honeypot_training_data.json (JSON format - ~1MB)")
    print("  3. honeypot_training_sample.csv (100 samples for testing)")
    print("\nNext steps:")
    print("  1. Upload honeypot_training_data.csv to Azure Blob Storage")
    print("  2. Path: training_data/honeypot_training_data.csv")
    print("  3. Deploy your backend to Azure")
    print("  4. Model will train automatically!")
    print("\n🚀 Ready to upload to Azure!")