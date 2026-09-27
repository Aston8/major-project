import asyncio
import motor.motor_asyncio
import sys

async def main():
    client = motor.motor_asyncio.AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["smartshield"]
    cursor = db.scans.find().sort("created_at", -1).limit(10)
    
    print("Latest Scans:")
    async for doc in cursor:
        sb = doc.get("sandbox_report") or {}
        print("-" * 50)
        print(f"Scan ID: {doc.get('_id')}")
        print(f"Type: {doc.get('type')}")
        print(f"Input: {doc.get('input_data')}")
        print(f"Sandbox Executed: {sb.get('executed')}")
        print(f"Sandbox Verdict: {sb.get('sandbox_verdict')}")
        print(f"Behavior Findings: {sb.get('behavior_findings')}")
        print(f"Qwen Verdict Score: {doc.get('qwen_result', {}).get('score')}")
        print(f"Final Score: {doc.get('fusion_result', {}).get('final_score')}")
        print(f"Final Category: {doc.get('fusion_result', {}).get('category')}")

if __name__ == "__main__":
    asyncio.run(main())
