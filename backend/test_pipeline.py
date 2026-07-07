import os
import sys
import asyncio
import logging

# Dynamically inject the absolute path of the backend directory into Python's module lookup registry
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Internal module imports can now resolve reliably across any terminal runtime environment
from app.data.pipeline import OSINTPipeline

# Enable console logging output for verification visibility
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

async def test_run():
    target_feeds = ["https://www.cisa.gov/cybersecurity-advisories/all.xml"]
    
    print("\n--- INITIATING SYSTEM INTEGRATION TEST ---")
    pipeline = OSINTPipeline(target_feeds=target_feeds)
    
    try:
        indicators = await pipeline.run()
        print(f"\n[SUCCESS] Pipeline Execution Completed.")
        print(f"[METRIC] Validated ThreatIndicator Model Instances Emitted: {len(indicators)}")
        
        if indicators:
            print("\n--- SAMPLE VALIDATED RECORD PROTOTYPE ---")
            sample = indicators[0]
            print(f"ID (UUIDv5):  {sample.id}")
            print(f"Title:        {sample.title}")
            print(f"Risk Score:   {sample.risk_score}")
            print(f"Observed At:  {sample.observed_at}")
            print("-----------------------------------------\n")
            
    except Exception as e:
        print(f"\n[FAILURE] System Engine Alert. Pipeline crashed: {str(e)}")
    finally:
        await pipeline.close()

if __name__ == "__main__":
    asyncio.run(test_run())