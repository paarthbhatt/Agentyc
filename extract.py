import json

with open(r'C:\Users\Parth\.gemini\antigravity-ide\brain\1e6c158c-60dc-440d-b33f-66c12125702f\.system_generated\logs\transcript_full.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        data = json.loads(line)
        if data.get('type') == 'USER_INPUT':
            with open('initial_prompt.txt', 'a', encoding='utf-8') as out:
                out.write(data['content'] + "\n---\n")
