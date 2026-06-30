import json
import sys

def run():
    path = r'C:\Users\Parth\.gemini\antigravity-ide\brain\1e6c158c-60dc-440d-b33f-66c12125702f\.system_generated\logs\transcript.jsonl'
    with open('all_inputs.txt', 'w', encoding='utf-8') as out:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                data = json.loads(line)
                if data.get('type') == 'USER_INPUT':
                    content = data.get('content', '')
                    out.write(content + "\n---\n")

if __name__ == '__main__':
    run()
