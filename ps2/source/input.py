import json
import sys

if __name__ == "__main__":
    artifacts = json.load(sys.stdin)
    print(json.dumps({k: v["input"] for k, v in artifacts.items()}, indent=4))
